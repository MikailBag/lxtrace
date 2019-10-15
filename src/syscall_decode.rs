//! This module implements decoding syscalls into human readable types
//! Also is provides additional metadata (e.g. fd Ray ID)

use crate::{
    magic::{
        self,
        ty::{PrimitiveTy, Ty},
        Magic,
    },
    DecodedArg, RawSyscall, Syscall,
};

use nix::{
    sys::uio::{process_vm_readv, IoVec, RemoteIoVec},
    unistd::Pid,
};

pub(crate) struct Decoder<'a> {
    magic: &'a Magic,
}

const MAX_LEN: usize = 1024;

impl<'a> Decoder<'a> {
    fn try_read_zstring(&self, ptr: usize, proc: Pid) -> Option<Vec<u8>> {
        let mut out_buf = Vec::new();

        // TODO buffered read
        while out_buf.len() < MAX_LEN {
            match self.try_read_string(ptr + out_buf.len(), 1, proc) {
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

    fn try_read_string(&self, ptr: usize, len: usize, proc: Pid) -> Option<Vec<u8>> {
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

    fn decode_argument(
        &self,
        value: u64,
        data_type: &crate::magic::ty::Ty,
        subject: Pid,
        _raw_args: &RawSyscall,
    ) -> DecodedArg {
        match data_type {
            Ty::Primitive(PrimitiveTy::Fd) => DecodedArg::Handle(value as u32, None),
            Ty::Primitive(PrimitiveTy::Number) => DecodedArg::Num(i128::from(value)),
            Ty::Primitive(PrimitiveTy::ZString) => {
                let mut result = DecodedArg::Unknown;
                if let Some(buf) = self.try_read_zstring(value as usize, subject) {
                    result = DecodedArg::String(String::from_utf8_lossy(&buf).to_string());
                }
                /*if let Some(len_arg) = data_type.len_arg {
                    let read_base = value as usize;
                    let read_cnt = raw_args.args[len_arg as usize] as usize;
                    if let Some(buf) = self.try_read_string(read_base, read_cnt, subject) {
                        result = DecodedArg::String(String::from_utf8_lossy(&buf).to_string());
                    }
                }*/

                result
            }
            _ => DecodedArg::Unknown,
        }
    }

    pub(crate) fn process(&mut self, syscall: &RawSyscall, pid: Pid) -> Option<Syscall> {
        let syscall_id = magic::hir::SyscallId(syscall.syscall_id as u32);
        let syscall_spec = match self.magic.lookup_syscall_by_id(syscall_id) {
            Some(spec) => spec,
            None => {
                return None;
            }
        };
        let it = syscall_spec.params().map(|(i, field_def)| {
            self.decode_argument(
                syscall.args[i],
                self.magic.resolve_ty(&field_def.ty),
                pid,
                syscall,
            )
        });

        Some(Syscall {
            name: syscall_spec.name.clone(),
            args_decoded: it.collect(),
        })
    }

    pub fn new(magic: &'a Magic) -> Decoder<'a> {
        Decoder { magic }
    }
}
