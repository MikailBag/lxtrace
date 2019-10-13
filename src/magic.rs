pub mod hir;
mod parse_tree;
mod raw;
pub mod ty;

use pest::Parser;

pub use hir::Hir as Magic;

pub fn init(s: &str) -> Magic {
    let p = match raw::P::parse(raw::Rule::input, s) {
        Ok(ast) => ast,
        Err(err) => {
            eprintln!("magic file syntax error: \n{}", err);
            std::process::exit(1);
        }
    };
    let parse_tree = parse_tree::new(p);
    let mut hir = hir::lower::lower(parse_tree).expect("magic file syntax error");
    hir::ty_collect::collect_types(&mut hir);
    hir
}
