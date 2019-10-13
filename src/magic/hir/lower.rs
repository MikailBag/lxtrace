//! Performs parse tree -> hir conversion
use crate::magic::{hir, parse_tree};
use anyhow::Context;

fn lower_def_body(ast: parse_tree::DefBody) -> hir::DefBody {
    fn lower_field_def(ast: parse_tree::FieldDef) -> hir::FieldDef {
        let name = ast.name();
        let ty = ast.ty();
        hir::FieldDef {
            name: name.to_string(),
            ty: ty.to_string(),
        }
    }
    let fields = ast.fields().map(lower_field_def).collect();
    hir::DefBody { fields }
}

fn lower_syscall_def(syscall_def_ast: parse_tree::SyscallDef) -> anyhow::Result<hir::SyscallDef> {
    let name = syscall_def_ast.name();
    let mut attrs = syscall_def_ast.attrs();
    let syscall_id = match attrs.remove("id") {
        Some(id) => id.parse().context("Failed to parse `id` attribute")?,
        None => {
            anyhow::bail!("`id` attribute not set");
        }
    };
    Ok(hir::SyscallDef {
        id: hir::SyscallId(syscall_id),
        name: name.to_string(),
        body: lower_def_body(syscall_def_ast.def_body()),
    })
}

fn lower_def(def_ast: parse_tree::ItemDef) -> anyhow::Result<hir::ItemDef> {
    let def = match def_ast {
        parse_tree::ItemDef::Syscall(def) => hir::ItemDef::Syscall(lower_syscall_def(def)?),
    };
    Ok(def)
}

pub(in crate::magic) fn lower(pt: parse_tree::Input) -> anyhow::Result<hir::Hir> {
    Ok(hir::Hir {
        defs: pt.defs().map(|def| {
            let def_name = def.name().to_string();
            match lower_def(def) {
                ok @ Ok(_) => ok,
                Err(err) => {
                    Err(err.context(format!("failed to lower definition `{}`", def_name)))
                }
            }
        }).collect::<Result<Vec<_>, _>>()?,
        types: hir::ty_db::TyDb::default()
    })
}
