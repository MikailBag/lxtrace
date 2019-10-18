//! Performs parse tree -> hir conversion
use crate::magic::{hir, parse_tree};
use anyhow::Context;

fn lower_def_body(ast: parse_tree::DefBody) -> hir::DefBody {
    fn lower_field_def(ast: parse_tree::FieldDef) -> hir::FieldDef {
        let name = ast.name();
        let ty = ast.ty();
        let attrs = ast.attrs();
        let ty_info = hir::FieldTypeInfo {
            ty_name: ty.to_string(),
            len_ref: attrs
                .get("len")
                .map(|len| len.split("::").map(ToOwned::to_owned).collect())
                .unwrap_or_else(Vec::new),
        };
        hir::FieldDef {
            name: name.to_string(),
            ty_info,
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
    let strategy = match attrs.get("kind") {
        Some(s) => match *s {
            "in" => hir::SyscallAnalyzeStrategy {
                on_enter: true,
                on_exit: false,
            },
            "out" => hir::SyscallAnalyzeStrategy {
                on_enter: false,
                on_exit: true,
            },
            "inout" => hir::SyscallAnalyzeStrategy {
                on_enter: true,
                on_exit: true,
            },
            _ => anyhow::bail!("unknown `kind` attr value: {}", s),
        },
        None => hir::SyscallAnalyzeStrategy {
            on_enter: false,
            on_exit: true,
        },
    };
    Ok(hir::SyscallDef {
        id: hir::SyscallId(syscall_id),
        name: name.to_string(),
        body: lower_def_body(syscall_def_ast.def_body()),
        strategy,
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
        defs: pt
            .defs()
            .map(|def| {
                let def_name = def.name().to_string();
                match lower_def(def) {
                    ok @ Ok(_) => ok,
                    Err(err) => {
                        Err(err.context(format!("failed to lower definition `{}`", def_name)))
                    }
                }
            })
            .collect::<Result<Vec<_>, _>>()?,
        types: hir::ty_db::TyDb::default(),
    })
}
