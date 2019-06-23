use pest_derive::Parser;
use std::{collections::HashMap, error::Error, fmt, str::FromStr};

#[derive(Debug, Clone, Copy)]
pub enum DataKind {
    /// not used in this syscall
    Null,
    /// handle
    Fd,
    /// pointer to process memory
    User,
    /// number
    Number,
    /// string
    String,
}

#[derive(Debug, Clone, Copy)]
pub struct ArgType {
    pub is_in: bool,
    pub is_out: bool,
    pub kind: DataKind,
}

#[derive(Debug)]
pub struct RetType {
    pub kind: DataKind,
}

#[derive(Debug)]
pub struct SyscallSpec {
    pub name: String,
    pub id: u32,
    pub arg_count: u8,
    pub args: [ArgType; 6],
    pub ret: RetType,
}

#[derive(Parser)]
#[grammar = "./magic.pest"]
struct TypeParse;

impl FromStr for ArgType {
    type Err = ();
    fn from_str(s: &str) -> Result<ArgType, Self::Err> {
        use pest::Parser;
        let mut res = TypeParse::parse(Rule::arg_type, s).unwrap();
        let res = res.next().unwrap();
        let mut data_kind = None;
        let mut is_in = false;
        let mut is_out = false;
        for child in res.into_inner() {
            match child.as_rule() {
                Rule::arg_type_name => {
                    let new_data_kind = match child.as_str() {
                        "fd" => DataKind::Fd,
                        "num" => DataKind::Number,
                        "string" => DataKind::String,
                        "user" => DataKind::User,
                        _ => unreachable!(),
                    };
                    assert!(data_kind.is_none());
                    data_kind.replace(new_data_kind);
                }
                Rule::EOI => break,
                Rule::arg_flags => {
                    for child in child.into_inner() {
                        match child.as_str() {
                            "in" => {
                                assert_eq!(is_in, false);
                                is_in = true;
                            }
                            "out" => {
                                assert_eq!(is_out, false);
                                is_out = true;
                            }
                            _ => unreachable!(),
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        Ok(ArgType {
            is_in,
            is_out,
            kind: data_kind.unwrap(),
        })
    }
}

impl SyscallSpec {
    fn parse(inp: &serde_json::Value) -> SyscallSpec {
        let inp = inp.as_object().unwrap();
        let name = inp.get("name").unwrap().as_str().unwrap().to_string();
        let id = inp.get("id").unwrap().as_u64().map(|x| x as u32).unwrap();
        let ret_type: ArgType = inp.get("ret").unwrap().as_str().unwrap().parse().unwrap();
        let arg_cnt = inp.get("arg_count").unwrap().as_u64().unwrap();
        assert!(arg_cnt <= 6);
        let empty_arg_type = ArgType {
            is_in: false,
            is_out: false,
            kind: DataKind::Null,
        };
        let mut args = [empty_arg_type; 6];
        for i in 0..arg_cnt {
            let i = i as usize;
            let arg_spec = inp.get(&format!("arg{}", i + 1)).unwrap();
            let arg_spec = arg_spec.as_str().unwrap();
            args[i] = arg_spec.parse().unwrap();
        }

        SyscallSpec {
            name,
            id,
            arg_count: arg_cnt as u8,
            args,
            ret: RetType {
                kind: ret_type.kind,
            },
        }
    }
}

#[derive(Debug)]
pub struct MagicDb {
    syscalls: HashMap<u32, SyscallSpec>,
}

impl MagicDb {
    pub fn spec_by_id(&self, id: u32) -> Option<&SyscallSpec> {
        self.syscalls.get(&id)
    }
}

pub fn init(magic: &serde_json::Value) -> MagicDb {
    let magic = magic.as_array().unwrap();
    let mut data = vec![];
    for x in magic {
        let spec = SyscallSpec::parse(x);
        data.push(spec);
    }

    let syscalls = data
        .into_iter()
        .map(|syscall_spec| (syscall_spec.id, syscall_spec))
        .collect();
    MagicDb { syscalls }
}
