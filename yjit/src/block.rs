use crate::{
    backend::ir::{Assembler, Opnd, Target, CFP, SP},
    codegen::CodePtr,
    core::{TempMapping, Type, TypeDiff, YARVOpnd},
    cruby::{rb_callable_method_entry_t, IseqPtr, RUBY_OFFSET_CFP_JIT_RETURN, SIZEOF_VALUE},
    jit_state::JITState,
    options::get_option,
    stats::incr_counter_by,
};
use std::hash::Hash;
use std::{
    cell::{Ref, RefCell, RefMut},
    collections::HashSet,
    hash::Hasher,
    mem,
    rc::Rc,
};

// Maximum number of temp value types we keep track of
pub const MAX_TEMP_TYPES: usize = 8;

// Maximum number of local variable types we keep track of
pub const MAX_LOCAL_TYPES: usize = 8;

/// Code generation context
/// Contains information we can use to specialize/optimize code
/// There are a lot of context objects so we try to keep the size small.
#[derive(Clone, Default, PartialEq, Debug)]
pub struct Context {
    // Number of values currently on the temporary stack
    pub stack_size: u8,

    // Offset of the JIT SP relative to the interpreter SP
    // This represents how far the JIT's SP is from the "real" SP
    pub sp_offset: i8,

    // Depth of this block in the sidechain (eg: inline-cache chain)
    pub chain_depth: u8,

    // Local variable types we keep track of
    pub local_types: [Type; MAX_LOCAL_TYPES],

    // Temporary variable types we keep track of
    pub temp_types: [Type; MAX_TEMP_TYPES],

    // Type we track for self
    pub self_type: Type,

    // Mapping of temp stack entries to types we track
    pub temp_mapping: [TempMapping; MAX_TEMP_TYPES],
}

impl Context {
    pub fn get_stack_size(&self) -> u8 {
        self.stack_size
    }

    pub fn get_sp_offset(&self) -> i8 {
        self.sp_offset
    }

    pub fn set_sp_offset(&mut self, offset: i8) {
        self.sp_offset = offset;
    }

    pub fn get_chain_depth(&self) -> u8 {
        self.chain_depth
    }

    pub fn reset_chain_depth(&mut self) {
        self.chain_depth = 0;
    }

    pub fn increment_chain_depth(&mut self) {
        self.chain_depth += 1;
    }

    /// Get an operand for the adjusted stack pointer address
    pub fn sp_opnd(&self, offset_bytes: isize) -> Opnd {
        let offset = ((self.sp_offset as isize) * (SIZEOF_VALUE as isize)) + offset_bytes;
        let offset = offset as i32;
        Opnd::mem(64, SP, offset)
    }

    /// Push one new value on the temp stack with an explicit mapping
    /// Return a pointer to the new stack top
    pub fn stack_push_mapping(&mut self, (mapping, temp_type): (TempMapping, Type)) -> Opnd {
        // If type propagation is disabled, store no types
        if get_option!(no_type_prop) {
            return self.stack_push_mapping((mapping, Type::Unknown));
        }

        let stack_size: usize = self.stack_size.into();

        // Keep track of the type and mapping of the value
        if stack_size < MAX_TEMP_TYPES {
            self.temp_mapping[stack_size] = mapping;
            self.temp_types[stack_size] = temp_type;

            if let TempMapping::Local(idx) = mapping {
                assert!((idx as usize) < MAX_LOCAL_TYPES);
            }
        }

        self.stack_size += 1;
        self.sp_offset += 1;

        self.stack_opnd(0)
    }

    /// Push one new value on the temp stack
    /// Return a pointer to the new stack top
    pub fn stack_push(&mut self, val_type: Type) -> Opnd {
        self.stack_push_mapping((TempMapping::Stack, val_type))
    }

    /// Push the self value on the stack
    pub fn stack_push_self(&mut self) -> Opnd {
        self.stack_push_mapping((TempMapping::ToSelf, Type::Unknown))
    }

    /// Push a local variable on the stack
    pub fn stack_push_local(&mut self, local_idx: usize) -> Opnd {
        if local_idx >= MAX_LOCAL_TYPES {
            return self.stack_push(Type::Unknown);
        }

        self.stack_push_mapping((TempMapping::Local((local_idx as u8).into()), Type::Unknown))
    }

    // Pop N values off the stack
    // Return a pointer to the stack top before the pop operation
    pub fn stack_pop(&mut self, n: usize) -> Opnd {
        assert!(n <= self.stack_size.into());

        let top = self.stack_opnd(0);

        // Clear the types of the popped values
        for i in 0..n {
            let idx: usize = (self.stack_size as usize) - i - 1;

            if idx < MAX_TEMP_TYPES {
                self.temp_types[idx] = Type::Unknown;
                self.temp_mapping[idx] = TempMapping::Stack;
            }
        }

        self.stack_size -= n as u8;
        self.sp_offset -= n as i8;

        top
    }

    pub fn shift_stack(&mut self, argc: usize) {
        assert!(argc < self.stack_size.into());

        let method_name_index = (self.stack_size as usize) - argc - 1;

        for i in method_name_index..(self.stack_size - 1) as usize {
            if i + 1 < MAX_TEMP_TYPES {
                self.temp_types[i] = self.temp_types[i + 1];
                self.temp_mapping[i] = self.temp_mapping[i + 1];
            }
        }
        self.stack_pop(1);
    }

    /// Get an operand pointing to a slot on the temp stack
    pub fn stack_opnd(&self, idx: i32) -> Opnd {
        Opnd::Stack {
            idx,
            sp_offset: self.sp_offset,
            num_bits: 64,
        }
    }

    /// Get the type of an instruction operand
    pub fn get_opnd_type(&self, opnd: YARVOpnd) -> Type {
        match opnd {
            YARVOpnd::SelfOpnd => self.self_type,
            YARVOpnd::StackOpnd(idx) => {
                assert!(idx < self.stack_size);
                let stack_idx: usize = (self.stack_size - 1 - idx).into();

                // If outside of tracked range, do nothing
                if stack_idx >= MAX_TEMP_TYPES {
                    return Type::Unknown;
                }

                let mapping = self.temp_mapping[stack_idx];

                match mapping {
                    TempMapping::ToSelf => self.self_type,
                    TempMapping::Stack => self.temp_types[(self.stack_size - 1 - idx) as usize],
                    TempMapping::Local(idx) => {
                        assert!((idx as usize) < MAX_LOCAL_TYPES);
                        self.local_types[idx as usize]
                    }
                }
            }
        }
    }

    /// Get the currently tracked type for a local variable
    pub fn get_local_type(&self, idx: usize) -> Type {
        *self.local_types.get(idx).unwrap_or(&Type::Unknown)
    }

    /// Upgrade (or "learn") the type of an instruction operand
    /// This value must be compatible and at least as specific as the previously known type.
    /// If this value originated from self, or an lvar, the learned type will be
    /// propagated back to its source.
    pub fn upgrade_opnd_type(&mut self, opnd: YARVOpnd, opnd_type: Type) {
        // If type propagation is disabled, store no types
        if get_option!(no_type_prop) {
            return;
        }

        match opnd {
            YARVOpnd::SelfOpnd => self.self_type.upgrade(opnd_type),
            YARVOpnd::StackOpnd(idx) => {
                assert!(idx < self.stack_size);
                let stack_idx = (self.stack_size - 1 - idx) as usize;

                // If outside of tracked range, do nothing
                if stack_idx >= MAX_TEMP_TYPES {
                    return;
                }

                let mapping = self.temp_mapping[stack_idx];

                match mapping {
                    TempMapping::ToSelf => self.self_type.upgrade(opnd_type),
                    TempMapping::Stack => self.temp_types[stack_idx].upgrade(opnd_type),
                    TempMapping::Local(idx) => {
                        let idx = idx as usize;
                        assert!(idx < MAX_LOCAL_TYPES);
                        self.local_types[idx].upgrade(opnd_type);
                    }
                }
            }
        }
    }

    /*
    Get both the type and mapping (where the value originates) of an operand.
    This is can be used with stack_push_mapping or set_opnd_mapping to copy
    a stack value's type while maintaining the mapping.
    */
    pub fn get_opnd_mapping(&self, opnd: YARVOpnd) -> (TempMapping, Type) {
        let opnd_type = self.get_opnd_type(opnd);

        match opnd {
            YARVOpnd::SelfOpnd => (TempMapping::ToSelf, opnd_type),
            YARVOpnd::StackOpnd(idx) => {
                assert!(idx < self.stack_size);
                let stack_idx = (self.stack_size - 1 - idx) as usize;

                if stack_idx < MAX_TEMP_TYPES {
                    (self.temp_mapping[stack_idx], opnd_type)
                } else {
                    // We can't know the source of this stack operand, so we assume it is
                    // a stack-only temporary. type will be UNKNOWN
                    assert!(opnd_type == Type::Unknown);
                    (TempMapping::Stack, opnd_type)
                }
            }
        }
    }

    /// Overwrite both the type and mapping of a stack operand.
    pub fn set_opnd_mapping(&mut self, opnd: YARVOpnd, (mapping, opnd_type): (TempMapping, Type)) {
        match opnd {
            YARVOpnd::SelfOpnd => unreachable!("self always maps to self"),
            YARVOpnd::StackOpnd(idx) => {
                assert!(idx < self.stack_size);
                let stack_idx = (self.stack_size - 1 - idx) as usize;

                // If type propagation is disabled, store no types
                if get_option!(no_type_prop) {
                    return;
                }

                // If outside of tracked range, do nothing
                if stack_idx >= MAX_TEMP_TYPES {
                    return;
                }

                self.temp_mapping[stack_idx] = mapping;

                // Only used when mapping == MAP_STACK
                self.temp_types[stack_idx] = opnd_type;
            }
        }
    }

    /// Set the type of a local variable
    pub fn set_local_type(&mut self, local_idx: usize, local_type: Type) {
        let ctx = self;

        // If type propagation is disabled, store no types
        if get_option!(no_type_prop) {
            return;
        }

        if local_idx >= MAX_LOCAL_TYPES {
            return;
        }

        // If any values on the stack map to this local we must detach them
        for (i, mapping) in ctx.temp_mapping.iter_mut().enumerate() {
            *mapping = match *mapping {
                TempMapping::Stack => TempMapping::Stack,
                TempMapping::ToSelf => TempMapping::ToSelf,
                TempMapping::Local(idx) => {
                    if idx as usize == local_idx {
                        ctx.temp_types[i] = ctx.local_types[idx as usize];
                        TempMapping::Stack
                    } else {
                        TempMapping::Local(idx)
                    }
                }
            }
        }

        ctx.local_types[local_idx] = local_type;
    }

    /// Erase local variable type information
    /// eg: because of a call we can't track
    pub fn clear_local_types(&mut self) {
        // When clearing local types we must detach any stack mappings to those
        // locals. Even if local values may have changed, stack values will not.
        for (i, mapping) in self.temp_mapping.iter_mut().enumerate() {
            *mapping = match *mapping {
                TempMapping::Stack => TempMapping::Stack,
                TempMapping::ToSelf => TempMapping::ToSelf,
                TempMapping::Local(idx) => {
                    self.temp_types[i] = self.local_types[idx as usize];
                    TempMapping::Stack
                }
            }
        }

        // Clear the local types
        self.local_types = [Type::default(); MAX_LOCAL_TYPES];
    }

    /// Compute a difference score for two context objects
    pub fn diff(&self, dst: &Context) -> TypeDiff {
        // Self is the source context (at the end of the predecessor)
        let src = self;

        // Can only lookup the first version in the chain
        if dst.chain_depth != 0 {
            return TypeDiff::Incompatible;
        }

        // Blocks with depth > 0 always produce new versions
        // Sidechains cannot overlap
        if src.chain_depth != 0 {
            return TypeDiff::Incompatible;
        }

        if dst.stack_size != src.stack_size {
            return TypeDiff::Incompatible;
        }

        if dst.sp_offset != src.sp_offset {
            return TypeDiff::Incompatible;
        }

        // Difference sum
        let mut diff = 0;

        // Check the type of self
        diff += match src.self_type.diff(dst.self_type) {
            TypeDiff::Compatible(diff) => diff,
            TypeDiff::Incompatible => return TypeDiff::Incompatible,
        };

        // For each local type we track
        for i in 0..src.local_types.len() {
            let t_src = src.local_types[i];
            let t_dst = dst.local_types[i];
            diff += match t_src.diff(t_dst) {
                TypeDiff::Compatible(diff) => diff,
                TypeDiff::Incompatible => return TypeDiff::Incompatible,
            };
        }

        // For each value on the temp stack
        for i in 0..src.stack_size {
            let (src_mapping, src_type) = src.get_opnd_mapping(YARVOpnd::StackOpnd(i));
            let (dst_mapping, dst_type) = dst.get_opnd_mapping(YARVOpnd::StackOpnd(i));

            // If the two mappings aren't the same
            if src_mapping != dst_mapping {
                if dst_mapping == TempMapping::Stack {
                    // We can safely drop information about the source of the temp
                    // stack operand.
                    diff += 1;
                } else {
                    return TypeDiff::Incompatible;
                }
            }

            diff += match src_type.diff(dst_type) {
                TypeDiff::Compatible(diff) => diff,
                TypeDiff::Incompatible => return TypeDiff::Incompatible,
            };
        }

        TypeDiff::Compatible(diff)
    }

    pub fn two_fixnums_on_stack(&self, jit: &mut JITState) -> Option<bool> {
        if jit.at_current_insn() {
            let comptime_recv = jit.peek_at_stack(self, 1);
            let comptime_arg = jit.peek_at_stack(self, 0);
            return Some(comptime_recv.fixnum_p() && comptime_arg.fixnum_p());
        }

        let recv_type = self.get_opnd_type(YARVOpnd::StackOpnd(1));
        let arg_type = self.get_opnd_type(YARVOpnd::StackOpnd(0));
        match (recv_type, arg_type) {
            (Type::Fixnum, Type::Fixnum) => Some(true),
            (Type::Unknown | Type::UnknownImm, Type::Unknown | Type::UnknownImm) => None,
            _ => Some(false),
        }
    }
}

/// Tuple of (iseq, idx) used to identify basic blocks
/// There are a lot of blockid objects so we try to keep the size small.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(packed)]
pub struct BlockId {
    /// Instruction sequence
    pub iseq: IseqPtr,

    /// Index in the iseq where the block starts
    pub idx: u32,
}

/// Basic block version
/// Represents a portion of an iseq compiled with a given context
/// Note: care must be taken to minimize the size of block_t objects
#[derive(Clone, Debug)]
pub struct Block {
    // Bytecode sequence (iseq, idx) this is a version of
    pub blockid: BlockId,

    // Index one past the last instruction for this block in the iseq
    pub end_idx: u32,

    // Context at the start of the block
    // This should never be mutated
    pub ctx: Context,

    // Positions where the generated code starts and ends
    pub start_addr: CodePtr,
    pub end_addr: Option<CodePtr>,

    // List of incoming branches (from predecessors)
    // These are reference counted (ownership shared between predecessor and successors)
    pub incoming: Vec<BranchRef>,

    // NOTE: we might actually be able to store the branches here without refcounting
    // however, using a RefCell makes it easy to get a pointer to Branch objects
    //
    // List of outgoing branches (to successors)
    pub outgoing: Box<[BranchRef]>,

    // FIXME: should these be code pointers instead?
    // Offsets for GC managed objects in the mainline code block
    pub gc_obj_offsets: Box<[u32]>,

    // CME dependencies of this block, to help to remove all pointers to this
    // block in the system.
    pub cme_dependencies: Box<[CmePtr]>,

    // Code address of an exit for `ctx` and `blockid`.
    // Used for block invalidation.
    pub entry_exit: Option<CodePtr>,
}

impl Block {
    pub fn make_ref(blockid: BlockId, ctx: &Context, start_addr: CodePtr) -> BlockRef {
        let block = Block {
            blockid,
            end_idx: 0,
            ctx: ctx.clone(),
            start_addr,
            end_addr: None,
            incoming: Vec::new(),
            outgoing: Box::new([]),
            gc_obj_offsets: Box::new([]),
            cme_dependencies: Box::new([]),
            entry_exit: None,
        };

        // Wrap the block in a reference counted refcell
        // so that the block ownership can be shared
        BlockRef::new(Rc::new(RefCell::new(block)))
    }

    pub fn get_blockid(&self) -> BlockId {
        self.blockid
    }

    pub fn get_end_idx(&self) -> u32 {
        self.end_idx
    }

    pub fn get_ctx(&self) -> Context {
        self.ctx.clone()
    }

    pub fn get_ctx_count(&self) -> usize {
        let mut count = 1; // block.ctx
        for branch in self.outgoing.iter() {
            count += branch.borrow().get_stub_count();
        }
        count
    }

    #[allow(unused)]
    pub fn get_start_addr(&self) -> CodePtr {
        self.start_addr
    }

    #[allow(unused)]
    pub fn get_end_addr(&self) -> Option<CodePtr> {
        self.end_addr
    }

    /// Get an immutable iterator over cme dependencies
    pub fn iter_cme_deps(&self) -> std::slice::Iter<'_, CmePtr> {
        self.cme_dependencies.iter()
    }

    /// Set the end address in the generated for the block
    /// This can be done only once for a block
    pub fn set_end_addr(&mut self, addr: CodePtr) {
        // TODO: assert constraint that blocks can shrink but not grow in length
        self.end_addr = Some(addr);
    }

    /// Set the index of the last instruction in the block
    /// This can be done only once for a block
    pub fn set_end_idx(&mut self, end_idx: u32) {
        assert!(self.end_idx == 0);
        self.end_idx = end_idx;
    }

    pub fn set_gc_obj_offsets(self: &mut Block, gc_offsets: Vec<u32>) {
        assert_eq!(self.gc_obj_offsets.len(), 0);
        if !gc_offsets.is_empty() {
            incr_counter_by!(num_gc_obj_refs, gc_offsets.len());
            self.gc_obj_offsets = gc_offsets.into_boxed_slice();
        }
    }

    /// Instantiate a new CmeDependency struct and add it to the list of
    /// dependencies for this block.
    pub fn set_cme_dependencies(&mut self, cme_dependencies: Vec<CmePtr>) {
        self.cme_dependencies = cme_dependencies.into_boxed_slice();
    }

    // Push an incoming branch ref and shrink the vector
    pub fn push_incoming(&mut self, branch: BranchRef) {
        self.incoming.push(branch);
        self.incoming.shrink_to_fit();
    }

    // Push an outgoing branch ref and shrink the vector
    pub fn set_outgoing(&mut self, outgoing: Vec<BranchRef>) {
        self.outgoing = outgoing.into_boxed_slice();
    }

    // Compute the size of the block code
    pub fn code_size(&self) -> usize {
        (self.end_addr.unwrap().raw_ptr() as usize) - (self.start_addr.raw_ptr() as usize)
    }
}

/// Reference-counted pointer to a block that can be borrowed mutably.
/// Wrapped so we could implement [Hash] and [Eq] for use with stdlib collections.
#[derive(Debug)]
pub struct BlockRef(Rc<RefCell<Block>>);

/// Reference-counted pointer to a branch that can be borrowed mutably
pub type BranchRef = Rc<RefCell<Branch>>;

/// List of block versions for a given blockid
pub type VersionList = Vec<BlockRef>;

/// Map from iseq indices to lists of versions for that given blockid
/// An instance of this is stored on each iseq
type VersionMap = Vec<VersionList>;

/// This is all the data YJIT stores on an iseq
/// This will be dynamically allocated by C code
/// C code should pass an &mut IseqPayload to us
/// when calling into YJIT
#[derive(Default)]
pub struct IseqPayload {
    // Basic block versions
    pub version_map: VersionMap,

    // Indexes of code pages used by this this ISEQ
    pub pages: HashSet<usize>,

    // Blocks that are invalidated but are not yet deallocated.
    // The code GC will free them later.
    pub dead_blocks: Vec<BlockRef>,
}

impl IseqPayload {
    /// Remove all block versions from the payload and then return them as an iterator
    pub fn take_all_blocks(&mut self) -> impl Iterator<Item = BlockRef> {
        // Empty the blocks
        let version_map = mem::take(&mut self.version_map);

        // Turn it into an iterator that owns the blocks and return
        version_map.into_iter().flatten()
    }
}

impl BlockRef {
    /// Constructor
    pub fn new(rc: Rc<RefCell<Block>>) -> Self {
        Self(rc)
    }

    /// Borrow the block through [RefCell].
    pub fn borrow(&self) -> Ref<'_, Block> {
        self.0.borrow()
    }

    /// Borrow the block for mutation through [RefCell].
    pub fn borrow_mut(&self) -> RefMut<'_, Block> {
        self.0.borrow_mut()
    }
}

impl Clone for BlockRef {
    /// Clone the [Rc]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl Hash for BlockRef {
    /// Hash the reference by hashing the pointer
    fn hash<H: Hasher>(&self, state: &mut H) {
        let rc_ptr = Rc::as_ptr(&self.0);
        rc_ptr.hash(state);
    }
}

impl PartialEq for BlockRef {
    /// Equality defined by allocation identity
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

/// It's comparison by identity so all the requirements are satisfied
impl Eq for BlockRef {}

/// Branch code shape enumeration
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BranchShape {
    Next0,   // Target 0 is next
    Next1,   // Target 1 is next
    Default, // Neither target is next
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchGenFn {
    BranchIf(BranchShape),
    BranchNil(BranchShape),
    BranchUnless(BranchShape),
    JumpToTarget0(BranchShape),
    JNZToTarget0,
    JZToTarget0,
    JBEToTarget0,
    JITReturn,
}

impl From<CodePtr> for Target {
    fn from(code_ptr: CodePtr) -> Self {
        Target::CodePtr(code_ptr)
    }
}

impl BranchGenFn {
    pub fn call(self, asm: &mut Assembler, target0: CodePtr, target1: Option<CodePtr>) {
        match self {
            BranchGenFn::BranchIf(shape) => match shape {
                BranchShape::Next0 => asm.jz(target1.unwrap().into()),
                BranchShape::Next1 => asm.jnz(target0.into()),
                BranchShape::Default => {
                    asm.jnz(target0.into());
                    asm.jmp(target1.unwrap().into());
                }
            },
            BranchGenFn::BranchNil(shape) => match shape {
                BranchShape::Next0 => asm.jne(target1.unwrap().into()),
                BranchShape::Next1 => asm.je(target0.into()),
                BranchShape::Default => {
                    asm.je(target0.into());
                    asm.jmp(target1.unwrap().into());
                }
            },
            BranchGenFn::BranchUnless(shape) => match shape {
                BranchShape::Next0 => asm.jnz(target1.unwrap().into()),
                BranchShape::Next1 => asm.jz(target0.into()),
                BranchShape::Default => {
                    asm.jz(target0.into());
                    asm.jmp(target1.unwrap().into());
                }
            },
            BranchGenFn::JumpToTarget0(shape) => {
                if shape == BranchShape::Next1 {
                    panic!("Branch shape Next1 not allowed in JumpToTarget0!");
                }
                if shape == BranchShape::Default {
                    asm.jmp(target0.into());
                }
            }
            BranchGenFn::JNZToTarget0 => asm.jnz(target0.into()),
            BranchGenFn::JZToTarget0 => asm.jz(Target::CodePtr(target0)),
            BranchGenFn::JBEToTarget0 => asm.jbe(Target::CodePtr(target0)),
            BranchGenFn::JITReturn => {
                asm.comment("update cfp->jit_return");
                asm.mov(
                    Opnd::mem(64, CFP, RUBY_OFFSET_CFP_JIT_RETURN),
                    Opnd::const_ptr(target0.raw_ptr()),
                );
            }
        }
    }

    pub fn get_shape(self) -> BranchShape {
        match self {
            BranchGenFn::BranchIf(shape)
            | BranchGenFn::BranchNil(shape)
            | BranchGenFn::BranchUnless(shape)
            | BranchGenFn::JumpToTarget0(shape) => shape,
            BranchGenFn::JNZToTarget0
            | BranchGenFn::JZToTarget0
            | BranchGenFn::JBEToTarget0
            | BranchGenFn::JITReturn => BranchShape::Default,
        }
    }

    pub fn set_shape(&mut self, new_shape: BranchShape) {
        match self {
            BranchGenFn::BranchIf(shape)
            | BranchGenFn::BranchNil(shape)
            | BranchGenFn::BranchUnless(shape) => {
                *shape = new_shape;
            }
            BranchGenFn::JumpToTarget0(shape) => {
                if new_shape == BranchShape::Next1 {
                    panic!("Branch shape Next1 not allowed in JumpToTarget0!");
                }
                *shape = new_shape;
            }
            BranchGenFn::JNZToTarget0
            | BranchGenFn::JZToTarget0
            | BranchGenFn::JBEToTarget0
            | BranchGenFn::JITReturn => {
                assert_eq!(new_shape, BranchShape::Default);
            }
        }
    }
}

/// A place that a branch could jump to
#[derive(Debug)]
pub enum BranchTarget {
    Stub(Box<BranchStub>), // Not compiled yet
    Block(BlockRef),       // Already compiled
}

impl BranchTarget {
    pub fn get_address(&self) -> Option<CodePtr> {
        match self {
            BranchTarget::Stub(stub) => stub.address,
            BranchTarget::Block(blockref) => Some(blockref.borrow().start_addr),
        }
    }

    pub fn get_blockid(&self) -> BlockId {
        match self {
            BranchTarget::Stub(stub) => stub.id,
            BranchTarget::Block(blockref) => blockref.borrow().blockid,
        }
    }

    pub fn get_ctx(&self) -> Context {
        match self {
            BranchTarget::Stub(stub) => stub.ctx.clone(),
            BranchTarget::Block(blockref) => blockref.borrow().ctx.clone(),
        }
    }

    pub fn get_block(&self) -> Option<BlockRef> {
        match self {
            BranchTarget::Stub(_) => None,
            BranchTarget::Block(blockref) => Some(blockref.clone()),
        }
    }

    pub fn set_iseq(&mut self, iseq: IseqPtr) {
        match self {
            BranchTarget::Stub(stub) => stub.id.iseq = iseq,
            BranchTarget::Block(blockref) => blockref.borrow_mut().blockid.iseq = iseq,
        }
    }
}

#[derive(Debug)]
pub struct BranchStub {
    pub address: Option<CodePtr>,
    pub id: BlockId,
    pub ctx: Context,
}

/// Store info about an outgoing branch in a code segment
/// Note: care must be taken to minimize the size of branch objects
#[derive(Debug)]
pub struct Branch {
    // Block this is attached to
    pub block: BlockRef,

    // Positions where the generated code starts and ends
    pub start_addr: Option<CodePtr>,
    pub end_addr: Option<CodePtr>, // exclusive

    // Branch target blocks and their contexts
    pub targets: [Option<Box<BranchTarget>>; 2],

    // Branch code generation function
    pub gen_fn: BranchGenFn,
}

impl Branch {
    // Compute the size of the branch code
    pub fn code_size(&self) -> usize {
        (self.end_addr.unwrap().raw_ptr() as usize) - (self.start_addr.unwrap().raw_ptr() as usize)
    }

    /// Get the address of one of the branch destination
    pub fn get_target_address(&self, target_idx: usize) -> Option<CodePtr> {
        self.targets[target_idx]
            .as_ref()
            .and_then(|target| target.get_address())
    }

    fn get_stub_count(&self) -> usize {
        let mut count = 0;
        for target in self.targets.iter().flatten() {
            if let BranchTarget::Stub(_) = target.as_ref() {
                count += 1;
            }
        }
        count
    }
}

// In case a block is invalidated, this helps to remove all pointers to the block.
pub type CmePtr = *const rb_callable_method_entry_t;
