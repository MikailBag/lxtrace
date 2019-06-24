use pest_derive::Parser;
use std::{collections::HashMap, process::exit, str::FromStr};

#[derive(Debug, Clone, Copy)]
pub(crate) enum DataKind {
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
pub(crate) struct DataType {
    pub is_in: bool,
    pub is_out: bool,
    pub kind: DataKind,
    pub len_arg: Option<u8>,
}

#[derive(Debug)]
pub(crate) struct SyscallSpec {
    pub name: String,
    pub id: u32,
    pub arg_count: u8,
    pub args: [DataType; 6],
    pub ret: DataType,
}

#[derive(Parser)]
#[grammar = "./magic.pest"]
struct TypeParse;

impl FromStr for DataType {
    type Err = ();
    fn from_str(s: &str) -> Result<DataType, Self::Err> {
        use pest::Parser;
        let mut res = TypeParse::parse(Rule::Arg, s).unwrap();
        let res = res.next().unwrap();
        let mut data_kind = None;
        let mut is_in = false;
        let mut is_out = false;
        let mut len_arg = None;
        for child /*ArgTag*/ in res.into_inner() {
            let child = child.into_inner().next().unwrap();
            match child.as_rule() {
                Rule::ArgTagSimple => {
                    let word = child.as_str();
                    match word {
                        "in" => is_in = true,
                        "out" => is_out = true,
                        _ => {
                            eprintln!("unknown simple tag '{}' in magicfile", word);
                            exit(1);
                        }
                    }
                }
                Rule::ArgTagKV => {
                    let mut children = child.into_inner();
                    let key = children.next().unwrap().as_str();
                    let val = children.next().unwrap().as_str();
                    match key {
                        "kind" => {
                            let kind = match val {
                                "fd" => DataKind::Fd,
                                "num" => DataKind::Number,
                                "ptr" => DataKind::User,
                                "buf" => DataKind::String,
                                _ => {
                                    eprintln!("unknown argument kind {}", val);
                                    exit(1);
                                }
                            };
                            if data_kind.replace(kind).is_some() {
                                eprintln!("data kind is redefined");
                                exit(1);
                            }
                        }
                        "len" => {
                            let data: u8 = val.parse().unwrap_or_else(|err| {
                                eprintln!("got len={}, which is not integer: {}", val, err);
                                exit(1);
                            });
                            if data < 1 || data > 6 {
                                eprintln!("len is not argument id");
                                exit(1);
                            }
                            if len_arg.replace(data - 1).is_some() {
                                eprintln!("len arg id is redefined");
                                exit(1);
                            }
                        }
                        _ => unimplemented!()
                    }
                }
                Rule::EOI => {}
                _ => {
                    eprintln!("Unexpected AST item: {:?}", child);
                    exit(1);
                }
            }
        }
        Ok(DataType {
            is_in,
            is_out,
            kind: data_kind.unwrap(),
            len_arg,
        })
    }
}

impl SyscallSpec {
    fn parse(inp: &serde_json::Value) -> SyscallSpec {
        let inp = inp.as_object().unwrap();
        let name = inp.get("name").unwrap().as_str().unwrap().to_string();
        let id = inp.get("id").unwrap().as_u64().map(|x| x as u32).unwrap();
        let ret_type: DataType = inp.get("ret").unwrap().as_str().unwrap().parse().unwrap();
        let arg_cnt = inp.get("arg_count").unwrap().as_u64().unwrap();
        assert!(arg_cnt <= 6);
        let empty_arg_type = DataType {
            is_in: false,
            is_out: false,
            kind: DataKind::Null,
            len_arg: None,
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
            ret: ret_type,
        }
    }
}

#[derive(Debug)]
pub(crate) struct MagicDb {
    syscalls: HashMap<u32, SyscallSpec>,
}

impl MagicDb {
    pub(crate) fn spec_by_id(&self, id: u32) -> Option<&SyscallSpec> {
        self.syscalls.get(&id)
    }
}

pub(crate) fn init(magic: &serde_json::Value) -> MagicDb {
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
