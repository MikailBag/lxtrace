//! Why so small? We don't support user-defined types yet (struct, union, flags, etc)
use crate::magic::{
    hir,
};


pub(in crate::magic) fn collect_types(hir: &mut hir::Hir) {
    hir.types.insert_primitives();
}