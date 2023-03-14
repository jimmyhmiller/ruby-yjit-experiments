use std::os::raw::c_void;

use crate::{
    cruby::{
        rb_iseq_get_yjit_payload, rb_iseq_set_yjit_payload, rb_jit_cont_each_iseq,
        rb_yjit_for_each_iseq, IseqPtr,
    },
    dev::stats::incr_counter,
    meta::block::IseqPayload,
};

/// Get the payload for an iseq. For safety it's up to the caller to ensure the returned `&mut`
/// upholds aliasing rules and that the argument is a valid iseq.
pub fn get_iseq_payload(iseq: IseqPtr) -> Option<&'static mut IseqPayload> {
    let payload = unsafe { rb_iseq_get_yjit_payload(iseq) };
    let payload: *mut IseqPayload = payload.cast();
    unsafe { payload.as_mut() }
}

/// Get the payload object associated with an iseq. Create one if none exists.
pub fn get_or_create_iseq_payload(iseq: IseqPtr) -> &'static mut IseqPayload {
    type VoidPtr = *mut c_void;

    let payload_non_null = unsafe {
        let payload = rb_iseq_get_yjit_payload(iseq);
        if payload.is_null() {
            // Increment the compiled iseq count
            incr_counter!(compiled_iseq_count);

            // Allocate a new payload with Box and transfer ownership to the GC.
            // We drop the payload with Box::from_raw when the GC frees the iseq and calls us.
            // NOTE(alan): Sometimes we read from an iseq without ever writing to it.
            // We allocate in those cases anyways.
            let new_payload = IseqPayload::default();
            let new_payload = Box::into_raw(Box::new(new_payload));
            rb_iseq_set_yjit_payload(iseq, new_payload as VoidPtr);

            new_payload
        } else {
            payload as *mut IseqPayload
        }
    };

    // SAFETY: we should have the VM lock and all other Ruby threads should be asleep. So we have
    // exclusive mutable access.
    // Hmm, nothing seems to stop calling this on the same
    // iseq twice, though, which violates aliasing rules.
    unsafe { payload_non_null.as_mut() }.unwrap()
}

/// Iterate over all existing ISEQs
pub fn for_each_iseq<F: FnMut(IseqPtr)>(mut callback: F) {
    unsafe extern "C" fn callback_wrapper(iseq: IseqPtr, data: *mut c_void) {
        let callback: &mut &mut dyn FnMut(IseqPtr) -> bool = std::mem::transmute(&mut *data);
        callback(iseq);
    }
    let mut data: &mut dyn FnMut(IseqPtr) = &mut callback;
    unsafe { rb_yjit_for_each_iseq(Some(callback_wrapper), (&mut data) as *mut _ as *mut c_void) };
}

/// Iterate over all ISEQ payloads
pub fn for_each_iseq_payload<F: FnMut(&IseqPayload)>(mut callback: F) {
    for_each_iseq(|iseq| {
        if let Some(iseq_payload) = get_iseq_payload(iseq) {
            callback(iseq_payload);
        }
    });
}

/// Iterate over all on-stack ISEQs
pub fn for_each_on_stack_iseq<F: FnMut(IseqPtr)>(mut callback: F) {
    unsafe extern "C" fn callback_wrapper(iseq: IseqPtr, data: *mut c_void) {
        let callback: &mut &mut dyn FnMut(IseqPtr) -> bool = std::mem::transmute(&mut *data);
        callback(iseq);
    }
    let mut data: &mut dyn FnMut(IseqPtr) = &mut callback;
    unsafe { rb_jit_cont_each_iseq(Some(callback_wrapper), (&mut data) as *mut _ as *mut c_void) };
}

/// Iterate over all on-stack ISEQ payloads
pub fn for_each_on_stack_iseq_payload<F: FnMut(&IseqPayload)>(mut callback: F) {
    for_each_on_stack_iseq(|iseq| {
        if let Some(iseq_payload) = get_iseq_payload(iseq) {
            callback(iseq_payload);
        }
    });
}

/// Iterate over all NOT on-stack ISEQ payloads
pub fn for_each_off_stack_iseq_payload<F: FnMut(&mut IseqPayload)>(mut callback: F) {
    let mut on_stack_iseqs: Vec<IseqPtr> = vec![];
    for_each_on_stack_iseq(|iseq| {
        on_stack_iseqs.push(iseq);
    });
    for_each_iseq(|iseq| {
        if !on_stack_iseqs.contains(&iseq) {
            if let Some(iseq_payload) = get_iseq_payload(iseq) {
                callback(iseq_payload);
            }
        }
    })
}
