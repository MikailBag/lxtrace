//! High-level magic file representation
pub(super) mod lower;
mod ty_db;
pub(super) mod ty_collect;

use super::ty::Ty;

pub struct Hir {
    defs: Vec<ItemDef>,
    types: ty_db::TyDb
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
pub struct SyscallDef {
    pub id: SyscallId,
    pub name: String,
    pub body: DefBody,
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
            .take(self.params_count())
            .enumerate()
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
pub struct FieldDef {
    pub name: String,
    pub ty: String,
}
