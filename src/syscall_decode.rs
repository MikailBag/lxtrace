//! This module implements decoding syscalls into human readable types
//! Also is provides additional metadata (e.g. fd Ray ID)

use crate::{
    magic::{ArgType, DataKind, MagicDb},
    DecodedArg, RawSyscall, Syscall,
};

pub struct Decoder<'a> {
    db: &'a MagicDb,
}

impl<'a> Decoder<'a> {
    fn decode_argument(&self, value: u64, data_type: ArgType) -> DecodedArg {
        match data_type.kind {
            DataKind::Fd => DecodedArg::Handle(value as u32, None),
            DataKind::Number => DecodedArg::Num(value as i128),
            _ => DecodedArg::Unknown,
        }
    }

    pub fn process(&mut self, syscall: &RawSyscall) -> Option<Syscall> {
        let syscall_spec = match self.db.spec_by_id(syscall.syscall_id as u32) {
            Some(spec) => spec,
            None => {
                return None;
            }
        };
        let mut it = (0..6).map(|i| self.decode_argument(syscall.args[i], syscall_spec.args[i]));

        let args_decoded: [DecodedArg; 6] = [
            it.next().unwrap(),
            it.next().unwrap(),
            it.next().unwrap(),
            it.next().unwrap(),
            it.next().unwrap(),
            it.next().unwrap(),
        ];

        Some(Syscall {
            name: syscall_spec.name.clone(),
            args_decoded,
            arg_count: syscall_spec.arg_count,
        })
    }

    pub fn new(db: &MagicDb) -> Decoder {
        Decoder { db }
    }
}
