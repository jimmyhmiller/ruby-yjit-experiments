use crate::{
    backend::ir::{Opnd, SP},
    core::YARVOpnd,
    cruby::{
        rb_cArray, rb_cFalseClass, rb_cFloat, rb_cInteger, rb_cNilClass, rb_cString, rb_cSymbol,
        rb_cTrueClass, ruby_value_type, Qfalse, Qnil, Qtrue, RUBY_T_ARRAY, RUBY_T_FALSE,
        RUBY_T_FIXNUM, RUBY_T_FLOAT, RUBY_T_HASH, RUBY_T_NIL, RUBY_T_STRING, RUBY_T_SYMBOL,
        RUBY_T_TRUE, SIZEOF_VALUE, VALUE,
    },
    dev::options::get_option,
    meta::jit_state::JITState,
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

// Represent the type of a value (local/stack/self) in YJIT
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Type {
    Unknown,
    UnknownImm,
    UnknownHeap,
    Nil,
    True,
    False,
    Fixnum,
    Flonum,
    Hash,
    ImmSymbol,

    #[allow(unused)]
    HeapSymbol,

    TString, // An object with the T_STRING flag set, possibly an rb_cString
    CString, // An un-subclassed string of type rb_cString (can have instance vars in some cases)
    TArray,  // An object with the T_ARRAY flag set, possibly an rb_cArray
    CArray,  // An un-subclassed string of type rb_cArray (can have instance vars in some cases)

    BlockParamProxy, // A special sentinel value indicating the block parameter should be read from
                     // the current surrounding cfp
}

// Default initialization
impl Default for Type {
    fn default() -> Self {
        Type::Unknown
    }
}

impl Type {
    /// This returns an appropriate Type based on a known value
    pub fn from(val: VALUE) -> Type {
        if val.special_const_p() {
            if val.fixnum_p() {
                Type::Fixnum
            } else if val.nil_p() {
                Type::Nil
            } else if val == Qtrue {
                Type::True
            } else if val == Qfalse {
                Type::False
            } else if val.static_sym_p() {
                Type::ImmSymbol
            } else if val.flonum_p() {
                Type::Flonum
            } else {
                unreachable!("Illegal value: {:?}", val)
            }
        } else {
            #[cfg(not(test))]
            use crate::cruby::rb_block_param_proxy;
            // Core.rs can't reference rb_cString because it's linked by Rust-only tests.
            // But CString vs TString is only an optimisation and shouldn't affect correctness.
            #[cfg(not(test))]
            if val.class_of() == unsafe { rb_cString } {
                return Type::CString;
            }
            #[cfg(not(test))]
            if val.class_of() == unsafe { rb_cArray } {
                return Type::CArray;
            }
            // We likewise can't reference rb_block_param_proxy, but it's again an optimisation;
            // we can just treat it as a normal Object.
            #[cfg(not(test))]
            if val == unsafe { rb_block_param_proxy } {
                return Type::BlockParamProxy;
            }
            match val.builtin_type() {
                RUBY_T_ARRAY => Type::TArray,
                RUBY_T_HASH => Type::Hash,
                RUBY_T_STRING => Type::TString,
                _ => Type::UnknownHeap,
            }
        }
    }

    /// Check if the type is an immediate
    pub fn is_imm(&self) -> bool {
        matches!(
            self,
            Type::UnknownImm
                | Type::Nil
                | Type::True
                | Type::False
                | Type::Fixnum
                | Type::Flonum
                | Type::ImmSymbol
        )
    }

    /// Returns true when the type is not specific.
    pub fn is_unknown(&self) -> bool {
        matches!(self, Type::Unknown | Type::UnknownImm | Type::UnknownHeap)
    }

    /// Returns true when we know the VALUE is a specific handle type,
    /// such as a static symbol ([Type::ImmSymbol], i.e. true from RB_STATIC_SYM_P()).
    /// Opposite of [Self::is_unknown].
    pub fn is_specific(&self) -> bool {
        !self.is_unknown()
    }

    /// Check if the type is a heap object
    pub fn is_heap(&self) -> bool {
        matches!(
            self,
            Type::UnknownHeap
                | Type::TArray
                | Type::CArray
                | Type::Hash
                | Type::HeapSymbol
                | Type::TString
                | Type::CString
        )
    }

    /// Check if it's a T_ARRAY object (both TArray and CArray are T_ARRAY)
    pub fn is_array(&self) -> bool {
        matches!(self, Type::TArray | Type::CArray)
    }

    /// Returns an Option with the T_ value type if it is known, otherwise None
    pub fn known_value_type(&self) -> Option<ruby_value_type> {
        match self {
            Type::Nil => Some(RUBY_T_NIL),
            Type::True => Some(RUBY_T_TRUE),
            Type::False => Some(RUBY_T_FALSE),
            Type::Fixnum => Some(RUBY_T_FIXNUM),
            Type::Flonum => Some(RUBY_T_FLOAT),
            Type::TArray | Type::CArray => Some(RUBY_T_ARRAY),
            Type::Hash => Some(RUBY_T_HASH),
            Type::ImmSymbol | Type::HeapSymbol => Some(RUBY_T_SYMBOL),
            Type::TString | Type::CString => Some(RUBY_T_STRING),
            Type::Unknown | Type::UnknownImm | Type::UnknownHeap => None,
            Type::BlockParamProxy => None,
        }
    }

    /// Returns an Option with the class if it is known, otherwise None
    pub fn known_class(&self) -> Option<VALUE> {
        unsafe {
            match self {
                Type::Nil => Some(rb_cNilClass),
                Type::True => Some(rb_cTrueClass),
                Type::False => Some(rb_cFalseClass),
                Type::Fixnum => Some(rb_cInteger),
                Type::Flonum => Some(rb_cFloat),
                Type::ImmSymbol | Type::HeapSymbol => Some(rb_cSymbol),
                Type::CString => Some(rb_cString),
                Type::CArray => Some(rb_cArray),
                _ => None,
            }
        }
    }

    /// Returns an Option with the exact value if it is known, otherwise None
    #[allow(unused)] // not yet used
    pub fn known_exact_value(&self) -> Option<VALUE> {
        match self {
            Type::Nil => Some(Qnil),
            Type::True => Some(Qtrue),
            Type::False => Some(Qfalse),
            _ => None,
        }
    }

    /// Returns an Option boolean representing whether the value is truthy if known, otherwise None
    pub fn known_truthy(&self) -> Option<bool> {
        match self {
            Type::Nil => Some(false),
            Type::False => Some(false),
            Type::UnknownHeap => Some(true),
            Type::Unknown | Type::UnknownImm => None,
            _ => Some(true),
        }
    }

    /// Returns an Option boolean representing whether the value is equal to nil if known, otherwise None
    pub fn known_nil(&self) -> Option<bool> {
        match (self, self.known_truthy()) {
            (Type::Nil, _) => Some(true),
            (Type::False, _) => Some(false), // Qfalse is not nil
            (_, Some(true)) => Some(false),  // if truthy, can't be nil
            (_, _) => None,                  // otherwise unknown
        }
    }

    /// Compute a difference between two value types
    pub fn diff(self, dst: Self) -> TypeDiff {
        // Perfect match, difference is zero
        if self == dst {
            return TypeDiff::Compatible(0);
        }

        // Any type can flow into an unknown type
        if dst == Type::Unknown {
            return TypeDiff::Compatible(1);
        }

        // A CString is also a TString.
        if self == Type::CString && dst == Type::TString {
            return TypeDiff::Compatible(1);
        }

        // A CArray is also a TArray.
        if self == Type::CArray && dst == Type::TArray {
            return TypeDiff::Compatible(1);
        }

        // Specific heap type into unknown heap type is imperfect but valid
        if self.is_heap() && dst == Type::UnknownHeap {
            return TypeDiff::Compatible(1);
        }

        // Specific immediate type into unknown immediate type is imperfect but valid
        if self.is_imm() && dst == Type::UnknownImm {
            return TypeDiff::Compatible(1);
        }

        // Incompatible types
        TypeDiff::Incompatible
    }

    /// Upgrade this type into a more specific compatible type
    /// The new type must be compatible and at least as specific as the previously known type.
    pub fn upgrade(&mut self, src: Self) {
        // Here we're checking that src is more specific than self
        assert!(src.diff(*self) != TypeDiff::Incompatible);
        *self = src;
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum TypeDiff {
    // usize == 0: Same type
    // usize >= 1: Different but compatible. The smaller, the more compatible.
    Compatible(usize),
    Incompatible,
}

// Potential mapping of a value on the temporary stack to
// self, a local variable or constant so that we can track its type
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum TempMapping {
    Stack,  // Normal stack value
    ToSelf, // Temp maps to the self operand
    Local(LocalIndex), // Temp maps to a local variable with index
            //ConstMapping,         // Small constant (0, 1, 2, Qnil, Qfalse, Qtrue)
}

// Index used by MapToLocal. Using this instead of u8 makes TempMapping 1 byte.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum LocalIndex {
    Local0,
    Local1,
    Local2,
    Local3,
    Local4,
    Local5,
    Local6,
    Local7,
}

impl From<LocalIndex> for u8 {
    fn from(idx: LocalIndex) -> Self {
        match idx {
            LocalIndex::Local0 => 0,
            LocalIndex::Local1 => 1,
            LocalIndex::Local2 => 2,
            LocalIndex::Local3 => 3,
            LocalIndex::Local4 => 4,
            LocalIndex::Local5 => 5,
            LocalIndex::Local6 => 6,
            LocalIndex::Local7 => 7,
        }
    }
}

impl From<u8> for LocalIndex {
    fn from(idx: u8) -> Self {
        match idx {
            0 => LocalIndex::Local0,
            1 => LocalIndex::Local1,
            2 => LocalIndex::Local2,
            3 => LocalIndex::Local3,
            4 => LocalIndex::Local4,
            5 => LocalIndex::Local5,
            6 => LocalIndex::Local6,
            7 => LocalIndex::Local7,
            _ => unreachable!("{idx} was larger than {MAX_LOCAL_TYPES}"),
        }
    }
}

impl Default for TempMapping {
    fn default() -> Self {
        TempMapping::Stack
    }
}
