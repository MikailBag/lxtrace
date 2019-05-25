use nix::Result;
use std::os::unix::io::RawFd;
use std::mem;

fn write_all(fd: RawFd, data: &[u8]) -> Result<()> {
    let ptr = data.as_ptr();
    let total_len = data.len();
    let mut written = 0;
    while written < total_len {
        let subdata = std::slice::from_raw_parts(ptr.add(written), total_len - written);
        let cnt = nix::unistd::write(fd, subdata)?;
        written += cnt;
    }
    Ok(())
}
const DATA_LEN_LEN: usize = mem::size_of::<*const ()>();

fn read_all(fd: RawFd, num: usize) -> Result<Vec<u8>> {
    let mut out = vec![0; num];
    let sl = out.as_mut_slice();
    let mut nread = 0;
    while nread < num {
        let (_, rem) = sl.split_at_mut(nread);
        let cnt = nix::unistd::read(fd, rem)?;
        nread += cnt;
    }
    Ok(out)
}

pub struct Sender {
    fd: RawFd,
}

impl Drop for Sender {
    fn drop(&mut self) {
        libc::close(self.fd);
    }
}


impl Sender {
    pub fn send_bytes(&self, data: &[u8]) -> Result<()> {
        let data_len_msg = data.len().to_ne_bytes();
        write_all(self.fd, &data_len_msg)?;
        write_all(self.fd, data)
    }

    pub unsafe fn send<T>(&self, x: T) -> Result<()> {
        let bytes: &[u8] = unsafe { std::mem::transmute(x) };
        self.send_bytes(bytes)
    }
}

pub struct Receiver {
    fd: RawFd,
}

impl Drop for Receiver {
    fn drop(&mut self) {
        libc::close(self.fd);
    }
}


impl Receiver {
    pub fn receive_bytes(&self) -> Result<Vec<u8>> {
        // receive len
        let len_buf = read_all(self.fd, DATA_LEN_LEN)?;
        let mut len_bytes = [0; 8];
        len_bytes.copy_from_slice(&len_buf);
        let len = usize::from_ne_bytes(len_bytes);
        // receive data
        let data = read_all(self.fd, len)?;
        Ok(data)
    }

    // TODO don't panic
    pub unsafe fn receive<T>(&self) -> Result<T> {
        let data = self.receive_bytes()?;
        let t_size = std::mem::size_of::<T>();
        if data.len() != t_size {
            panic!("message has invalid size");
        }
        data.shrink_to_fit();
    }
}

pub fn make() -> Result<(Receiver, Sender)> {
    let flag = nix::fcnlt::OFlag::O_CLOEXEC;
    let (r, w) = nix::unistd::pipe2(flag)?;
    let recv = Receiver { fd: r };
    let send = Sender { fd: w };
    Ok((recv, send))
}
