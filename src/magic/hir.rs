//! High-level magic file representation
pub(super) mod lower;
pub(super) mod ty_collect;
mod ty_db;

use super::ty::Ty;

pub struct Hir {
    defs: Vec<ItemDef>,
    types: ty_db::TyDb,
}

impl Hir {
    pub fn lookup_syscall_by_id(&self, id: SyscallId) -> Option<&SyscallDef> {
        for def in &self.defs {
            match def {
                ItemDef::Syscall(syscall_def) => {
                    if syscall_def.id == id {
                        return Some(syscall_def);
                    }
                }
            }
        }
        None
    }

    pub fn resolve_ty(&self, name: &str) -> &Ty {
        self.types.lookup(name)
    }
}

pub enum ItemDef {
    Syscall(SyscallDef),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SyscallId(pub u32);

#[derive(Debug)]
pub struct SyscallAnalyzeStrategy {
    pub on_enter: bool,
    pub on_exit: bool,
}
#[derive(Debug)]
pub struct SyscallDef {
    pub id: SyscallId,
    pub name: String,
    pub body: DefBody,
    pub strategy: SyscallAnalyzeStrategy,
}

impl SyscallDef {
    pub fn params_count(&self) -> usize {
        let field_count = self.body.field_count();
        // one field is return value, other are parameters
        if field_count == 0 {
            dbg!(self);
            panic!("field_count must be non-zero")
        }
        field_count - 1
    }

    pub fn params(&self) -> impl Iterator<Item = (usize, &FieldDef)> {
        self.body
            .fields
            .iter()
            .filter(|field| field.name != "ret")
            .enumerate()
    }

    pub fn ret(&self) -> &FieldDef {
        self.body.fields.last().expect("empty DefBody")
    }
}

#[derive(Debug)]
pub struct DefBody {
    pub fields: Vec<FieldDef>,
}

impl DefBody {
    fn field_count(&self) -> usize {
        self.fields.len()
    }
}

#[derive(Debug)]
pub struct FieldTypeInfo {
    pub ty_name: String,
    pub len_ref: Vec<String>,
}

impl FieldTypeInfo {
    pub fn deps(&self) -> Vec<String> {
        let mut res = vec![];
        if !self.len_ref.is_empty() {
            res.push(self.len_ref[0].clone());
        }
        res
    }
}

#[derive(Debug)]
pub struct FieldDef {
    pub name: String,
    pub ty_info: FieldTypeInfo,
}
