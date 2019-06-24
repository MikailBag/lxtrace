//! This module implements decoding syscalls into human readable types
//! Also is provides additional metadata (e.g. fd Ray ID)

use crate::{
    magic::{DataKind, DataType, MagicDb},
    DecodedArg, RawSyscall, Syscall,
};

use nix::{
    sys::uio::{process_vm_readv, IoVec, RemoteIoVec},
    unistd::Pid,
};

pub(crate) struct Decoder<'a> {
    db: &'a MagicDb,
}

impl<'a> Decoder<'a> {
    fn try_read_string(&self, ptr: usize, len: usize, proc: Pid) -> Option<Vec<u8>> {
        let mut out_buf = Vec::new();
        match out_buf.try_reserve_exact(len) {
            Ok(_) => {}
            Err(_) => {
                // couldn't allocated memory
                // we ignore this error, because it can be caused by error in tracee as well
                return None;
            }
        }
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
        data_type: DataType,
        subject: Pid,
        raw_args: &RawSyscall,
    ) -> DecodedArg {
        match data_type.kind {
            DataKind::Fd => DecodedArg::Handle(value as u32, None),
            DataKind::Number => DecodedArg::Num(i128::from(value)),
            DataKind::String => {
                let mut result = DecodedArg::Unknown;
                if let Some(len_arg) = data_type.len_arg {
                    let read_base = value as usize;
                    let read_cnt = raw_args.args[len_arg as usize] as usize;
                    if let Some(buf) = self.try_read_string(read_base, read_cnt, subject) {
                        result = DecodedArg::String(String::from_utf8_lossy(&buf).to_string());
                    }
                }

                result
            }
            _ => DecodedArg::Unknown,
        }
    }

    pub(crate) fn process(&mut self, syscall: &RawSyscall, pid: Pid) -> Option<Syscall> {
        let syscall_spec = match self.db.spec_by_id(syscall.syscall_id as u32) {
            Some(spec) => spec,
            None => {
                return None;
            }
        };
        let it = (0..syscall_spec.arg_count as usize)
            .map(|i| self.decode_argument(syscall.args[i], syscall_spec.args[i], pid, syscall));

        Some(Syscall {
            name: syscall_spec.name.clone(),
            args_decoded: it.collect(),
        })
    }

    pub(crate) fn new(db: &MagicDb) -> Decoder {
        Decoder { db }
    }
}
