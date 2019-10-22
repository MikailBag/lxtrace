use serde::{Deserialize, Serialize};
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
        pub fn name(&self) -> &str {
            self.name.as_ref()
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