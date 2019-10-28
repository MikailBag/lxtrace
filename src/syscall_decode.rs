//! This module implements decoding syscalls into human readable types
//! Also is provides additional metadata (e.g. fd Ray ID)

use crate::{
    magic::{
        self,
        hir::{FieldTypeInfo, SyscallDef},
        ty::{PrimitiveTy, Ty, Value},
        Magic,
    },
    RawSyscall, Syscall,
};

use std::convert::TryFrom;

use nix::{
    sys::uio::{process_vm_readv, IoVec, RemoteIoVec},
    unistd::Pid,
};

pub(crate) struct Decoder<'a> {
    pub(crate) magic: &'a Magic,
    pub(crate) evaluated: Vec<Option<Value>>,
    pub(crate) raw: &'a RawSyscall,
    pub(crate) proc: Pid,
    pub(crate) syscall: &'a SyscallDef,
}

const MAX_LEN: usize = 4096;

fn try_read_buf(ptr: usize, len: usize, proc: Pid) -> Option<Vec<u8>> {
    let mut out_buf = Vec::new();

    // TODO: use fallible allocation + custom allocator

    if len > MAX_LEN {
        return None;
    }

    out_buf.reserve_exact(len);
    out_buf.resize(len, 0xBA);
    let local_iovec = IoVec::from_mut_slice(&mut out_buf);
    let remove_iovec = RemoteIoVec { base: ptr, len };
    let local_iovecs = &[local_iovec];
    let remote_iovecs = &[remove_iovec];
    match process_vm_readv(proc, local_iovecs, remote_iovecs) {
        Ok(_) => {}
        Err(_) => return None,
    };

    Some(out_buf)
}
fn try_read_zstring(ptr: usize, proc: Pid) -> Option<Vec<u8>> {
    let mut out_buf = Vec::new();

    // TODO buffered read
    while out_buf.len() < MAX_LEN {
        match try_read_buf(ptr + out_buf.len(), 1, proc) {
            Some(vec) => {
                debug_assert_eq!(vec.len(), 1);
                let ch = vec[0];
                if ch != 0 {
                    out_buf.push(ch);
                } else {
                    break;
                }
            }
            None => {
                return None;
            }
        }
    }
    Some(out_buf)
}

fn decode_error(value: u64) -> Option<Value> {
    let value = value as i64;
    if value >= 0 {
        return None;
    }
    const ERRNO_MAX: i64 = 4095;
    let value = -value;
    if value <= ERRNO_MAX {
        return Some(Value::Error(
            value as i32,
            nix::errno::Errno::from_i32(value as i32).desc().to_string(),
        ));
    }
    None
}

impl<'a> Decoder<'a> {
    fn resolve_path(&self, mut path: impl Iterator<Item = impl AsRef<str>>) -> Option<&Value> {
        let head = path.next()?;
        let head = head.as_ref();
        let mut field = None;
        for fl in self.syscall.params() {
            let fl_info = fl.1;
            if fl_info.name == head {
                field = Some(fl.0);
                break;
            }
        }
        let field = field?;

        let val = self.evaluated[field].as_ref()?;

        val.project(path)
    }

    fn do_decode(&mut self, ty: &Ty, value: u64, field_ty_info: &FieldTypeInfo) -> Value {
        match ty {
            Ty::Primitive(PrimitiveTy::Fd) => Value::Handle(value as u32, None),
            Ty::Primitive(PrimitiveTy::Number) => Value::Integral(value as i64),
            Ty::Primitive(PrimitiveTy::ZString) => {
                let mut result = Value::Unknown;
                if let Some(buf) = try_read_zstring(value as usize, self.proc) {
                    result = Value::String(String::from_utf8_lossy(&buf).to_string());
                }
                result
            }
            Ty::Primitive(PrimitiveTy::Buffer) => {
                let mut result = Value::Unknown;
                let len_arg_path = &field_ty_info.len_ref;
                if !len_arg_path.is_empty() {
                    let len = self.resolve_path(len_arg_path.iter());
                    if let Some(len) = len {
                        if let Value::Integral(len) = len {
                            let len = *len;
                            if len >= 0 {
                                let len = len as usize;
                                let buf = try_read_buf(value as usize, len, self.proc);
                                if let Some(buf) = buf {
                                    result = Value::Buffer(buf.into_boxed_slice());
                                }
                            }
                        }
                    }
                }

                result
            }
            Ty::Primitive(PrimitiveTy::Signal) => {
                let signal_id = value as i32;
                let signal_name = nix::sys::signal::Signal::try_from(signal_id)
                    .ok()
                    .map(nix::sys::signal::Signal::as_str);
                Value::Signal(signal_id, signal_name.map(ToString::to_string))
            }
            Ty::Primitive(PrimitiveTy::Address) => Value::Address(value),
            Ty::Null => Value::Unknown,
        }
    }

    fn do_decode_arg(&mut self, idx: usize) -> Value {
        let field = match self.syscall.params().nth(idx) {
            Some(field) => field.1,
            None => return Value::Unknown,
        };

        let value = self.raw.args[idx];
        let ty = self.magic.resolve_ty(&field.ty_info.ty_name);
        self.do_decode(ty, value, &field.ty_info)
    }

    fn do_decode_ret(&mut self) -> Value {
        let value = self.raw.ret;
        if let Some(err_val) = decode_error(value) {
            return err_val;
        }

        let field = self.syscall.ret();
        let ty = self.magic.resolve_ty(&field.ty_info.ty_name);
        self.do_decode(ty, value, &field.ty_info)
    }

    fn decode_arg(&mut self, idx: usize) {
        let val = self.do_decode_arg(idx);
        let old = std::mem::replace(&mut self.evaluated[idx], Some(val));
        assert!(old.is_none());
    }

    pub(crate) fn process(&mut self) -> Option<Syscall> {
        let syscall_id = magic::hir::SyscallId(self.raw.syscall_id as u32);
        let syscall_spec = match self.magic.lookup_syscall_by_id(syscall_id) {
            Some(spec) => spec,
            None => {
                return None;
            }
        };

        // TODO: .rev() is quick fix to ensure that we at first process size, and afterwards buffer
        // proper solution is build topsort
        for i in (0..self.syscall.params_count()).rev() {
            self.decode_arg(i);
        }
        for _ in self.syscall.params_count()..self.evaluated.len() {
            self.evaluated.pop();
        }
        let ret_val = self.do_decode_ret();
        self.evaluated.push(Some(ret_val));

        let evaluated = std::mem::replace(&mut self.evaluated, Vec::new());
        //dbg!(&evaluated);
        let args: Option<Vec<Value>> = evaluated.into_iter().collect();
        let mut args = args?;
        let ret = args
            .pop()
            .expect("args should contain at least return value");
        Some(Syscall {
            name: syscall_spec.name.clone(),
            args,
            ret: Some(ret),
            backtrace: None,
        })
    }
}
