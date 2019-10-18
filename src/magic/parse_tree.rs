//! Defines parse tree - thin typed wrapper for pest
use super::raw::Rule;
use std::collections::HashMap;

// Utilities
type N<'a> = pest::iterators::Pair<'a, Rule>;

pub(super) fn new(p: pest::iterators::Pairs<Rule>) -> Input {
    let pairs = p.collect::<Vec<_>>();
    assert_eq!(pairs.len(), 1);
    Input::new(pairs.into_iter().next().unwrap())
}

macro_rules! define_node {
    ($node_type: ident, $rule: expr) => {
        #[derive(Debug, Clone)]
        pub(super) struct $node_type<'a>(N<'a>);

        impl<'a> $node_type<'a> {
            pub(super) const RULE: Rule = $rule;

            pub(super) fn new(n: N<'a>) -> $node_type {
                assert_eq!(n.as_rule(), Self::RULE);
                $node_type(n)
            }

            fn children(&self) -> impl Iterator<Item = N<'a>> {
                self.0.clone().into_inner()
            }

            #[allow(dead_code)]
            fn child_at(&self, i: usize) -> N<'a> {
                self.children().skip(i).next().unwrap()
            }
        }
    };
}

fn checked_node_text(n: N, rule: Rule) -> &str {
    assert_eq!(n.as_rule(), rule);
    n.as_str()
}

pub(super) type Attrs<'a> = HashMap<&'a str, &'a str>;

fn create_attrs(n: N) -> Attrs {
    fn create_attr(n: N) -> (&str, &str) {
        assert_eq!(n.as_rule(), Rule::attr);
        let mut iter = n.into_inner();
        let k = iter.next().unwrap().as_str();
        let v = iter.next().unwrap().as_str();
        (k, v)
    }
    assert_eq!(n.as_rule(), Rule::attrs);
    n.into_inner().map(create_attr).collect()
}

// Nodes

define_node!(Input, Rule::input);
impl<'a> Input<'a> {
    pub(super) fn defs(&self) -> impl Iterator<Item = ItemDef> {
        self.children().filter_map(|child| match child.as_rule() {
            Rule::syscall_def => Some(ItemDef::Syscall(SyscallDef::new(child))),
            Rule::EOI => None,
            _ => unreachable!(),
        })
    }
}

define_node!(SyscallDef, Rule::syscall_def);

impl<'a> SyscallDef<'a> {
    pub(super) fn attrs(&self) -> Attrs {
        create_attrs(self.child_at(0))
    }
    pub(super) fn name(&self) -> &str {
        checked_node_text(self.child_at(1), Rule::ident)
    }
    pub(super) fn def_body(&self) -> DefBody {
        DefBody::new(self.child_at(2))
    }
}

define_node!(DefBody, Rule::def_body);

impl<'a> DefBody<'a> {
    pub(super) fn fields(&self) -> impl Iterator<Item = FieldDef> {
        self.children().map(FieldDef::new)
    }
}
define_node!(FieldDef, Rule::field_def);

impl<'a> FieldDef<'a> {
    pub(super) fn attrs(&self) -> Attrs {
        create_attrs(self.child_at(0))
    }

    pub(super) fn name(&self) -> &'a str {
        let node = self.child_at(1);
        checked_node_text(node, Rule::ident)
    }

    pub(super) fn ty(&self) -> &'a str {
        let node = self.child_at(2);
        checked_node_text(node, Rule::ident)
    }
}

pub(super) enum ItemDef<'a> {
    Syscall(SyscallDef<'a>),
}

impl<'a> ItemDef<'a> {
    pub(super) fn name(&self) -> &str {
        match self {
            ItemDef::Syscall(def) => def.name(),
        }
    }
}
