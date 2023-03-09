use std::ptr;

use crate::cruby::{
    get_cfp_ep, get_cfp_ep_level, get_cfp_pc, get_cfp_self, get_cfp_sp, get_ec_cfp,
    get_iseq_body_local_table_size,
};
use crate::{
    meta::block::{BlockRef, BranchRef, CmePtr},
    codegen::CodePtr,
    meta::context::Context,
    cruby::{insn_len, EcPtr, IseqPtr, VALUE, VM_ENV_DATA_INDEX_SPECVAL, VM_ENV_DATA_SIZE},
};

/// Code generation state
/// This struct only lives while code is being generated
pub struct JITState {
    // Block version being compiled
    pub block: BlockRef,

    // Instruction sequence this is associated with
    pub iseq: IseqPtr,

    // Index of the current instruction being compiled
    pub insn_idx: u32,

    // Opcode for the instruction being compiled
    pub opcode: usize,

    // PC of the instruction being compiled
    pub pc: *mut VALUE,

    // Side exit to the instruction being compiled. See :side-exit:.
    pub side_exit_for_pc: Option<CodePtr>,

    // Execution context when compilation started
    // This allows us to peek at run-time values
    pub ec: Option<EcPtr>,

    // Whether we need to record the code address at
    // the end of this bytecode instruction for global invalidation
    pub record_boundary_patch_point: bool,

    // The block's outgoing branches
    pub outgoing: Vec<BranchRef>,

    // The block's CME dependencies
    pub cme_dependencies: Vec<CmePtr>,
}

impl JITState {
    pub fn new(blockref: &BlockRef) -> Self {
        JITState {
            block: blockref.clone(),
            iseq: ptr::null(), // TODO: initialize this from the blockid
            insn_idx: 0,
            opcode: 0,
            pc: ptr::null_mut::<VALUE>(),
            side_exit_for_pc: None,
            ec: None,
            record_boundary_patch_point: false,
            outgoing: Vec::new(),
            cme_dependencies: Vec::new(),
        }
    }

    pub fn get_block(&self) -> BlockRef {
        self.block.clone()
    }

    pub fn get_insn_idx(&self) -> u32 {
        self.insn_idx
    }

    pub fn get_iseq(self: &JITState) -> IseqPtr {
        self.iseq
    }

    pub fn get_opcode(self: &JITState) -> usize {
        self.opcode
    }

    pub fn get_pc(self: &JITState) -> *mut VALUE {
        self.pc
    }

    pub fn get_arg(&self, arg_idx: isize) -> VALUE {
        // insn_len require non-test config
        #[cfg(not(test))]
        assert!(insn_len(self.get_opcode()) > (arg_idx + 1).try_into().unwrap());
        unsafe { *(self.pc.offset(arg_idx + 1)) }
    }

    // Get the index of the next instruction
    pub fn next_insn_idx(&self) -> u32 {
        self.insn_idx + insn_len(self.get_opcode())
    }

    // Check if we are compiling the instruction at the stub PC
    // Meaning we are compiling the instruction that is next to execute
    pub fn at_current_insn(&self) -> bool {
        let ec_pc: *mut VALUE = unsafe { get_cfp_pc(get_ec_cfp(self.ec.unwrap())) };
        ec_pc == self.pc
    }

    // Peek at the nth topmost value on the Ruby stack.
    // Returns the topmost value when n == 0.
    pub fn peek_at_stack(&self, ctx: &Context, n: isize) -> VALUE {
        assert!(self.at_current_insn());
        assert!(n < ctx.get_stack_size() as isize);

        // Note: this does not account for ctx->sp_offset because
        // this is only available when hitting a stub, and while
        // hitting a stub, cfp->sp needs to be up to date in case
        // codegen functions trigger GC. See :stub-sp-flush:.
        unsafe {
            let sp: *mut VALUE = get_cfp_sp(get_ec_cfp(self.ec.unwrap()));

            *(sp.offset(-1 - n))
        }
    }

    pub fn peek_at_self(&self) -> VALUE {
        unsafe { get_cfp_self(get_ec_cfp(self.ec.unwrap())) }
    }

    pub fn peek_at_local(&self, n: i32) -> VALUE {
        assert!(self.at_current_insn());

        let local_table_size: isize = unsafe { get_iseq_body_local_table_size(self.iseq) }
            .try_into()
            .unwrap();
        assert!(n < local_table_size.try_into().unwrap());

        unsafe {
            let ep = get_cfp_ep(get_ec_cfp(self.ec.unwrap()));
            let n_isize: isize = n.try_into().unwrap();
            let offs: isize = -(VM_ENV_DATA_SIZE as isize) - local_table_size + n_isize + 1;
            *ep.offset(offs)
        }
    }

    pub fn peek_at_block_handler(&self, level: u32) -> VALUE {
        assert!(self.at_current_insn());

        unsafe {
            let ep = get_cfp_ep_level(get_ec_cfp(self.ec.unwrap()), level);
            *ep.offset(VM_ENV_DATA_INDEX_SPECVAL as isize)
        }
    }

    // Push an outgoing branch ref
    pub fn push_outgoing(&mut self, branch: BranchRef) {
        self.outgoing.push(branch);
    }

    // Push a CME dependency
    pub fn push_cme_dependency(&mut self, cme: CmePtr) {
        self.cme_dependencies.push(cme);
    }
}
