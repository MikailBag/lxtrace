use std::collections::HashMap;
use crate::magic::ty::{Ty, PrimitiveTy};

/// Type Database
#[derive(Default)]
pub(super) struct TyDb {
    data: HashMap<String, Ty>
}

impl TyDb {
    pub(super) fn add(&mut self, name: &str, ty: Ty) {
        if self.data.insert(name.to_string(), ty).is_some() {
            panic!("type {} redefined", name);
        }
    }

    pub(super) fn lookup(&self, name: &str) -> &Ty {
        self.data.get(name).unwrap_or_else(|| panic!("Type {} is unknown", name))
    }

    pub(super) fn insert_primitives(&mut self) {
        self.add("fd", Ty::Primitive(PrimitiveTy::Fd));
        self.add("zstring", Ty::Primitive(PrimitiveTy::ZString));
        self.add("num", Ty::Primitive(PrimitiveTy::Number));
    }
}