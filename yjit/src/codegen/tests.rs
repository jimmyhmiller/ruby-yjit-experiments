use std::ptr;

use crate::{
    asm::OutlinedCb,
    codegen::globals::gen_leave_exit,
    cruby::{Qtrue, YARVINSN_putobject_INT2FIX_0_},
    meta::context::{Type, TypeDiff, YARVOpnd},
};

use super::{generator::CodeGenerator, *};

fn setup_codegen() -> (CodeGenerator, CodeBlock) {
    let blockid = BlockId {
        iseq: ptr::null(),
        idx: 0,
    };
    let cb = CodeBlock::new_dummy(256 * 1024);
    let block = Block::make_ref(blockid, &Context::default(), cb.get_write_ptr());
    (
        CodeGenerator::new(
            JITState::new(&block),
            Context::default(),
            Assembler::new(),
            OutlinedCb::wrap(CodeBlock::new_dummy(256 * 1024)),
        ),
        cb,
    )
}

#[test]
fn test_gen_leave_exit() {
    let (mut gen, _) = setup_codegen();
    gen_leave_exit(&mut gen.ocb);
    assert!(gen.ocb.unwrap().get_write_pos() > 0);
}

#[test]
fn test_gen_exit() {
    let (mut gen, mut cb) = setup_codegen();
    let mut asm = gen.swap_asm();
    CodeGenerator::gen_exit(std::ptr::null_mut::<VALUE>(), &mut asm, &gen.ctx.clone());
    asm.compile(&mut cb);
    assert!(cb.get_write_pos() > 0);
}

#[test]
fn test_get_side_exit() {
    let (mut gen, _) = setup_codegen();
    gen.get_side_exit(&gen.ctx.clone());
    assert!(gen.ocb.unwrap().get_write_pos() > 0);
}

#[test]
fn test_gen_check_ints() {
    let (mut gen, _cb) = setup_codegen();
    let side_exit = gen.ocb.unwrap().get_write_ptr().as_side_exit();
    gen.gen_check_ints(side_exit);
}

#[test]
fn test_gen_nop() {
    let (mut gen, mut cb) = setup_codegen();
    let status = gen.gen_nop();
    gen.asm.compile(&mut cb);

    assert_eq!(status, CodegenStatus::KeepCompiling);
    assert_eq!(gen.ctx.diff(&Context::default()), TypeDiff::Compatible(0));
    assert_eq!(cb.get_write_pos(), 0);
}

#[test]
fn test_gen_pop() {
    let (mut gen, _cb) = setup_codegen();
    gen.ctx.stack_push(Type::Fixnum);
    let status = gen.gen_pop();

    assert_eq!(status, CodegenStatus::KeepCompiling);
    assert_eq!(gen.ctx.diff(&Context::default()), TypeDiff::Compatible(0));
}

#[test]
fn test_gen_dup() {
    let (mut gen, mut cb) = setup_codegen();
    gen.ctx.stack_push(Type::Fixnum);
    let status = gen.gen_dup();

    assert_eq!(status, CodegenStatus::KeepCompiling);

    // Did we duplicate the type information for the Fixnum type?
    assert_eq!(Type::Fixnum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(0)));
    assert_eq!(Type::Fixnum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(1)));

    gen.asm.compile(&mut cb);
    assert!(cb.get_write_pos() > 0); // Write some movs
}

#[test]
fn test_gen_dupn() {
    let (mut gen, mut cb) = setup_codegen();
    gen.ctx.stack_push(Type::Fixnum);
    gen.ctx.stack_push(Type::Flonum);

    let mut value_array: [u64; 2] = [0, 2]; // We only compile for n == 2
    let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
    gen.jit.pc = pc;

    let status = gen.gen_dupn();

    assert_eq!(status, CodegenStatus::KeepCompiling);

    assert_eq!(Type::Fixnum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(3)));
    assert_eq!(Type::Flonum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(2)));
    assert_eq!(Type::Fixnum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(1)));
    assert_eq!(Type::Flonum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(0)));

    // TODO: this is writing zero bytes on x86. Why?
    gen.asm.compile(&mut cb);
    assert!(cb.get_write_pos() > 0); // Write some movs
}

#[test]
fn test_gen_swap() {
    let (mut gen, _cb) = setup_codegen();
    gen.ctx.stack_push(Type::Fixnum);
    gen.ctx.stack_push(Type::Flonum);

    let status = gen.gen_swap();

    let (_, tmp_type_top) = gen.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(0));
    let (_, tmp_type_next) = gen.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(1));

    assert_eq!(status, CodegenStatus::KeepCompiling);
    assert_eq!(tmp_type_top, Type::Fixnum);
    assert_eq!(tmp_type_next, Type::Flonum);
}

#[test]
fn test_putnil() {
    let (mut gen, mut cb) = setup_codegen();
    let status = gen.gen_putnil();

    let (_, tmp_type_top) = gen.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(0));

    assert_eq!(status, CodegenStatus::KeepCompiling);
    assert_eq!(tmp_type_top, Type::Nil);
    gen.asm.compile(&mut cb);
    assert!(cb.get_write_pos() > 0);
}

#[test]
fn test_putobject_qtrue() {
    // Test gen_putobject with Qtrue
    let (mut gen, mut cb) = setup_codegen();

    let mut value_array: [u64; 2] = [0, Qtrue.into()];
    let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
    gen.jit.pc = pc;

    let status = gen.gen_putobject();

    let (_, tmp_type_top) = gen.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(0));

    assert_eq!(status, CodegenStatus::KeepCompiling);
    assert_eq!(tmp_type_top, Type::True);
    gen.asm.compile(&mut cb);
    assert!(cb.get_write_pos() > 0);
}

#[test]
fn test_putobject_fixnum() {
    // Test gen_putobject with a Fixnum to test another conditional branch
    let (mut gen, mut cb) = setup_codegen();

    // The Fixnum 7 is encoded as 7 * 2 + 1, or 15
    let mut value_array: [u64; 2] = [0, 15];
    let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
    gen.jit.pc = pc;

    let status = gen.gen_putobject();

    let (_, tmp_type_top) = gen.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(0));

    assert_eq!(status, CodegenStatus::KeepCompiling);
    assert_eq!(tmp_type_top, Type::Fixnum);
    gen.asm.compile(&mut cb);
    assert!(cb.get_write_pos() > 0);
}

#[test]
fn test_int2fix() {
    let (mut gen, _cb) = setup_codegen();
    gen.jit.opcode = YARVINSN_putobject_INT2FIX_0_.into_usize();
    let status = gen.gen_putobject_int2fix();

    let (_, tmp_type_top) = gen.ctx.get_opnd_mapping(YARVOpnd::StackOpnd(0));

    // Right now we're not testing the generated machine code to make sure a literal 1 or 0 was pushed. I've checked locally.
    assert_eq!(status, CodegenStatus::KeepCompiling);
    assert_eq!(tmp_type_top, Type::Fixnum);
}

#[test]
fn test_putself() {
    let (mut gen, mut cb) = setup_codegen();
    let status = gen.gen_putself();

    assert_eq!(status, CodegenStatus::KeepCompiling);
    gen.asm.compile(&mut cb);
    assert!(cb.get_write_pos() > 0);
}

#[test]
fn test_gen_setn() {
    let (mut gen, mut cb) = setup_codegen();
    gen.ctx.stack_push(Type::Fixnum);
    gen.ctx.stack_push(Type::Flonum);
    gen.ctx.stack_push(Type::CString);

    let mut value_array: [u64; 2] = [0, 2];
    let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
    gen.jit.pc = pc;

    let status = gen.gen_setn();

    assert_eq!(status, CodegenStatus::KeepCompiling);

    assert_eq!(Type::CString, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(2)));
    assert_eq!(Type::Flonum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(1)));
    assert_eq!(Type::CString, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(0)));

    gen.asm.compile(&mut cb);
    assert!(cb.get_write_pos() > 0);
}

#[test]
fn test_gen_topn() {
    let (mut gen, mut cb) = setup_codegen();
    gen.ctx.stack_push(Type::Flonum);
    gen.ctx.stack_push(Type::CString);

    let mut value_array: [u64; 2] = [0, 1];
    let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
    gen.jit.pc = pc;

    let status = gen.gen_topn();

    assert_eq!(status, CodegenStatus::KeepCompiling);

    assert_eq!(Type::Flonum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(2)));
    assert_eq!(Type::CString, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(1)));
    assert_eq!(Type::Flonum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(0)));

    gen.asm.compile(&mut cb);
    assert!(cb.get_write_pos() > 0); // Write some movs
}

#[test]
fn test_gen_adjuststack() {
    let (mut gen, mut cb) = setup_codegen();
    gen.ctx.stack_push(Type::Flonum);
    gen.ctx.stack_push(Type::CString);
    gen.ctx.stack_push(Type::Fixnum);

    let mut value_array: [u64; 3] = [0, 2, 0];
    let pc: *mut VALUE = &mut value_array as *mut u64 as *mut VALUE;
    gen.jit.pc = pc;

    let status = gen.gen_adjuststack();

    assert_eq!(status, CodegenStatus::KeepCompiling);

    assert_eq!(Type::Flonum, gen.ctx.get_opnd_type(YARVOpnd::StackOpnd(0)));

    gen.asm.compile(&mut cb);
    assert!(cb.get_write_pos() == 0); // No instructions written
}

#[test]
fn test_gen_leave() {
    let (mut gen, _cb) = setup_codegen();
    // Push return value
    gen.ctx.stack_push(Type::Fixnum);
    gen.gen_leave();
}
