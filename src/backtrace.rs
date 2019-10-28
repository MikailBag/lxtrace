use serde::{Deserialize, Serialize};
use std::borrow::Cow;
#[derive(Debug, Serialize, Deserialize)]
pub struct Backtrace {
    pub(crate) threads: Vec<ThreadBacktrace>,
}
impl Backtrace {
    pub fn threads(&self) -> &[ThreadBacktrace] {
        &self.threads
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ThreadBacktrace {
    pub(crate) name: Option<String>,
    pub(crate) id: u32,
    pub(crate) frames: Vec<Frame>,
}

impl ThreadBacktrace {
    pub fn name(&self) -> Option<&str> {
        self.name.as_ref().map(String::as_ref)
    }
    pub fn frames(&self) -> &[Frame] {
        &self.frames
    }
    pub fn id(&self) -> u32 {
        self.id
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Frame {
    pub(crate) ip: usize,
    pub(crate) sym: Option<Symbol>,
}
impl Frame {
    pub fn ip(&self) -> usize {
        self.ip
    }

    pub fn sym(&self) -> Option<&Symbol> {
        self.sym.as_ref()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Symbol {
    pub(crate) name: String,
    pub(crate) offset: usize,
    pub(crate) addr: usize,
    pub(crate) size: usize,
}

impl Symbol {
    pub fn raw_name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn demangle(&self) -> Cow<str> {
        if let Ok(rust_sym) = rustc_demangle::try_demangle(self.raw_name()) {
            return Cow::Owned(rust_sym.as_str().to_string());
        }

        if let Ok(cpp_sym) = cpp_demangle::Symbol::new(self.raw_name()) {
            return Cow::Owned(cpp_sym.to_string());
        }

        Cow::Borrowed(self.raw_name())
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn addr(&self) -> usize {
        self.addr
    }

    pub fn size(&self) -> usize {
        self.size
    }
}
