use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "./magic.pest"]
pub(super) struct P;
