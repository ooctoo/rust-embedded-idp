//! Bounded loopback PostgreSQL wire relay for isolated registration tests.
//!
//! The relay never records frame contents.  It only counts selected frames and
//! physical EOFs, so a test can distinguish a driver closing its socket from
//! the relay closing it during cleanup.

use std::{
    io::{self, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
pub enum Cut {
    Startup,
    Begin,
    Configure,
    Query,
    Commit,
}

struct State {
    stop: AtomicBool,
    armed: AtomicBool,
    skip_selected: AtomicUsize,
    hits: AtomicUsize,
    peer_eof: AtomicUsize,
    hit_peer_eof: AtomicUsize,
    sockets: Mutex<Vec<TcpStream>>,
}

pub struct Relay {
    pub port: u16,
    shared: Arc<State>,
    thread: Option<JoinHandle<()>>,
}

impl Relay {
    pub fn new(target: SocketAddr, cut: Cut) -> Self {
        assert!(target.ip().is_loopback());
        let listener = TcpListener::bind("127.0.0.1:0").expect("relay listener");
        listener
            .set_nonblocking(true)
            .expect("relay listener nonblocking");
        let port = listener.local_addr().expect("relay address").port();
        let shared = Arc::new(State {
            stop: AtomicBool::new(false),
            armed: AtomicBool::new(false),
            skip_selected: AtomicUsize::new(0),
            hits: AtomicUsize::new(0),
            peer_eof: AtomicUsize::new(0),
            hit_peer_eof: AtomicUsize::new(0),
            sockets: Mutex::new(Vec::new()),
        });
        let state = Arc::clone(&shared);
        let worker = thread::spawn(move || {
            let mut children = Vec::new();
            while !state.stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((client, _)) => {
                        assert!(children.len() < 16, "relay connection bound");
                        let server = TcpStream::connect_timeout(&target, Duration::from_secs(1))
                            .expect("fresh loopback database");
                        for socket in [&client, &server] {
                            socket
                                .set_read_timeout(Some(Duration::from_millis(50)))
                                .expect("relay read timeout");
                            socket
                                .set_write_timeout(Some(Duration::from_secs(1)))
                                .expect("relay write timeout");
                            state
                                .sockets
                                .lock()
                                .expect("relay sockets")
                                .push(socket.try_clone().expect("relay socket clone"));
                        }
                        let connection_state = Arc::clone(&state);
                        children.push(thread::spawn(move || {
                            relay_connection(client, server, cut, connection_state)
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
            for child in children {
                child.join().expect("relay connection");
            }
        });
        Self {
            port,
            shared,
            thread: Some(worker),
        }
    }

    pub fn arm(&self) {
        self.arm_after(0);
    }

    /// Arm the relay and ignore the first `skip_selected` matching frames.
    /// Frames observed before this call are never counted or skipped.
    pub fn arm_after(&self, skip_selected: usize) {
        self.shared
            .skip_selected
            .store(skip_selected, Ordering::Release);
        self.shared.armed.store(true, Ordering::Release);
    }

    pub fn disarm(&self) {
        self.shared.armed.store(false, Ordering::Release);
    }

    pub fn wait_for_hits(&self, count: usize) -> bool {
        wait_for_counter(&self.shared.hits, count, Duration::from_secs(5))
    }

    pub fn hits(&self) -> usize {
        self.shared.hits.load(Ordering::Acquire)
    }

    pub fn peer_eof(&self) -> usize {
        self.shared.peer_eof.load(Ordering::Acquire)
    }

    /// EOF on a connection that actually reached the selected blackhole.
    pub fn hit_peer_eof(&self) -> usize {
        self.shared.hit_peer_eof.load(Ordering::Acquire)
    }

    pub fn wait_for_peer_eof(&self, count: usize) -> bool {
        wait_for_counter(&self.shared.peer_eof, count, Duration::from_secs(2))
    }

    pub fn wait_for_hit_peer_eof(&self, count: usize) -> bool {
        wait_for_counter(&self.shared.hit_peer_eof, count, Duration::from_secs(2))
    }

    pub fn close(&mut self) {
        self.shared.stop.store(true, Ordering::Release);
        for socket in self.shared.sockets.lock().expect("relay sockets").iter() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        if let Some(worker) = self.thread.take() {
            worker.join().expect("relay worker");
        }
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        self.close();
    }
}

fn wait_for_counter(counter: &AtomicUsize, count: usize, timeout: Duration) -> bool {
    let limit = Instant::now() + timeout;
    while counter.load(Ordering::Acquire) < count {
        if Instant::now() >= limit {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
    true
}

fn read_exact(stream: &mut TcpStream, bytes: &mut [u8], state: &State) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() && !state.stop.load(Ordering::Acquire) {
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => offset += n,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    if offset == bytes.len() {
        Ok(())
    } else {
        Err(io::ErrorKind::Interrupted.into())
    }
}

fn relay_connection(mut client: TcpStream, mut server: TcpStream, cut: Cut, state: Arc<State>) {
    let muted = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let mut receive = None;
    let result = (|| -> io::Result<()> {
        // sslmode=disable sends one untyped startup packet.  sslmode=require
        // first sends PostgreSQL's eight-byte SSLRequest and waits for exactly
        // one response byte before any encrypted bytes are exchanged.
        let mut size = [0u8; 4];
        read_exact(&mut client, &mut size, &state)?;
        let length = u32::from_be_bytes(size) as usize;
        if !(8..=65_536).contains(&length) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut startup = vec![0; length - 4];
        read_exact(&mut client, &mut startup, &state)?;
        let ssl_request = length == 8
            && startup
                .get(..4)
                .is_some_and(|code| code == 80877103_u32.to_be_bytes());
        server.write_all(&size)?;
        server.write_all(&startup)?;

        if ssl_request {
            let mut response = [0u8; 1];
            read_exact(&mut server, &mut response, &state)?;
            let selected = matches!(cut, Cut::Startup)
                && state.armed.load(Ordering::Acquire)
                && consume_skip_or_mute(&muted, &state);
            if !selected {
                client.write_all(&response)?;
            }
            receive = Some(spawn_receiver(&client, &server, &state, &muted, &finished));
            if selected {
                // The selected blackhole consumes only the SSL negotiation
                // response.  Do not proxy encrypted client bytes to Postgres;
                // the client must close its own pending TLS operation.
                return discard_client_until_eof(&mut client, &state);
            }
            return relay_raw(&mut client, &mut server, &state);
        }

        receive = Some(spawn_receiver(&client, &server, &state, &muted, &finished));
        loop {
            let mut header = [0u8; 5];
            read_exact(&mut client, &mut header, &state)?;
            let length = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
            if !(4..=65_536).contains(&length) {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let mut payload = vec![0; length - 4];
            read_exact(&mut client, &mut payload, &state)?;
            let selected = match cut {
                Cut::Startup => false,
                Cut::Query => header[0] == b'P',
                _ => {
                    header[0] == b'Q'
                        && match cut {
                            Cut::Begin => {
                                payload == b"BEGIN\0" || payload.starts_with(b"START TRANSACTION")
                            }
                            Cut::Commit => payload == b"COMMIT\0",
                            Cut::Configure => payload.starts_with(b"SET LOCAL"),
                            _ => false,
                        }
                }
            };
            if selected && state.armed.load(Ordering::Acquire) {
                consume_skip_or_mute(&muted, &state);
            }
            server.write_all(&header)?;
            server.write_all(&payload)?;
        }
    })();

    if result
        .as_ref()
        .is_err_and(|error| error.kind() == io::ErrorKind::UnexpectedEof)
    {
        state.peer_eof.fetch_add(1, Ordering::AcqRel);
        if muted.load(Ordering::Acquire) {
            state.hit_peer_eof.fetch_add(1, Ordering::AcqRel);
        }
    }
    finished.store(true, Ordering::Release);
    let _ = server.shutdown(Shutdown::Both);
    let _ = client.shutdown(Shutdown::Both);
    if let Some(receive) = receive {
        receive.join().expect("relay receive");
    }
}

fn spawn_receiver(
    client: &TcpStream,
    server: &TcpStream,
    state: &Arc<State>,
    muted: &Arc<AtomicBool>,
    finished: &Arc<AtomicBool>,
) -> JoinHandle<()> {
    let mut server_read = server.try_clone().expect("relay server clone");
    let mut client_write = client.try_clone().expect("relay client clone");
    let receive_state = Arc::clone(state);
    let receive_muted = Arc::clone(muted);
    let receive_finished = Arc::clone(finished);
    thread::spawn(move || {
        let mut buf = [0u8; 8192];
        while !receive_state.stop.load(Ordering::Acquire)
            && !receive_finished.load(Ordering::Acquire)
        {
            match server_read.read(&mut buf) {
                Ok(0) => {
                    if !receive_muted.load(Ordering::Acquire) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(n) if !receive_muted.load(Ordering::Acquire) => {
                    if client_write.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => break,
            }
        }
        let _ = client_write.shutdown(Shutdown::Both);
    })
}

fn relay_raw(client: &mut TcpStream, server: &mut TcpStream, state: &State) -> io::Result<()> {
    let mut buf = [0u8; 8192];
    while !state.stop.load(Ordering::Acquire) {
        match client.read(&mut buf) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => server.write_all(&buf[..n])?,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::ErrorKind::Interrupted.into())
}

fn discard_client_until_eof(client: &mut TcpStream, state: &State) -> io::Result<()> {
    let mut buf = [0u8; 8192];
    while !state.stop.load(Ordering::Acquire) {
        match client.read(&mut buf) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::ErrorKind::Interrupted.into())
}

/// Returns true when this frame becomes the blackholed frame.
fn consume_skip_or_mute(muted: &AtomicBool, state: &State) -> bool {
    if muted.load(Ordering::Acquire) {
        return false;
    }
    loop {
        let remaining = state.skip_selected.load(Ordering::Acquire);
        if remaining == 0 {
            if !muted.swap(true, Ordering::AcqRel) {
                state.hits.fetch_add(1, Ordering::AcqRel);
                return true;
            }
            return false;
        }
        if state
            .skip_selected
            .compare_exchange(
                remaining,
                remaining - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            return false;
        }
    }
}
