use chrono::TimeZone;
use clap::{App, Arg};
use crossbeam_channel::{Receiver, Sender, bounded};
use regex::Regex;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_RESPONSE_SIZE: usize = 50 * 1024 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(15);
const LOG_FLUSH_INTERVAL: Duration = Duration::from_secs(5);

fn get_optimal_settings() -> (usize, usize, usize, Duration) {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let memory_mb = get_available_memory_mb();

    let buffer_size = match std::env::consts::OS {
        "windows" => (64 * 1024).min(memory_mb * 1024 / 100),
        "linux" => (128 * 1024).min(memory_mb * 1024 / 50),
        "macos" => (64 * 1024).min(memory_mb * 1024 / 100),
        _ => 32 * 1024,
    };

    let max_threads = (cpu_count * 8).min(match std::env::consts::OS {
        "linux" => 1024,
        "windows" => 256,
        "macos" => 512,
        _ => 128,
    });

    let batch_size = if memory_mb > 4096 {
        3000.min(max_threads * 2)
    } else if memory_mb > 2048 {
        2000.min(max_threads)
    } else {
        1000.min(max_threads / 2)
    };

    let flush_interval = if cpu_count >= 8 {
        Duration::from_secs(3)
    } else {
        Duration::from_secs(5)
    };

    (buffer_size, max_threads, batch_size, flush_interval)
}

fn get_available_memory_mb() -> usize {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            for line in content.lines() {
                if line.starts_with("MemAvailable:") {
                    if let Some(kb) = line.split_whitespace().nth(1) {
                        return kb.parse::<usize>().unwrap_or(4096 * 1024) / 1024;
                    }
                }
            }
        }
    }
    4096
}

fn get_optimal_buffer_size() -> usize {
    get_optimal_settings().0
}

fn get_optimal_thread_count() -> usize {
    get_optimal_settings().1
}

fn get_optimal_batch_size() -> usize {
    get_optimal_settings().2
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Rule {
    name: String,
    pattern: String,
    action: String,
    replacement: Option<String>,
    #[serde(skip)]
    compiled_regex: Option<Regex>,
}

impl Rule {
    fn compile(&mut self) -> Result<(), regex::Error> {
        match Regex::new(&self.pattern) {
            Ok(regex) => {
                self.compiled_regex = Some(regex);
                Ok(())
            }
            Err(e) => {
                eprintln!(
                    "Regex compilation failed for pattern '{}': {}",
                    self.pattern, e
                );
                Err(e)
            }
        }
    }

    fn matches(&self, content: &str) -> bool {
        match &self.compiled_regex {
            Some(regex) => regex.is_match(content),
            None => {
                eprintln!("Rule '{}' has no compiled regex", self.name);
                false
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct TrafficLog {
    timestamp: u64,
    timestamp_human: String,
    session_id: String,
    src_addr: String,
    dst_addr: String,
    method: String,
    url: String,
    full_url: String,
    status: u16,
    request_size: usize,
    response_size: usize,
    duration_micros: u64,
    duration_ms: f64,
    is_https: bool,
    user_agent: String,
    content_type: String,
    headers: HashMap<String, String>,
    request_headers: HashMap<String, String>,
    response_headers: HashMap<String, String>,
    blocked: bool,
    rule_matched: Option<String>,
    bytes_transferred: usize,
    connection_reused: bool,
}

impl TrafficLog {
    fn new(
        session_id: String,
        src_addr: String,
        dst_addr: String,
        method: String,
        url: String,
        full_url: String,
        status: u16,
        request_size: usize,
        response_size: usize,
        start_time: Instant,
        is_https: bool,
        request_headers: HashMap<String, String>,
        response_headers: HashMap<String, String>,
        blocked: bool,
        rule_matched: Option<String>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let timestamp_human = chrono::Utc
            .timestamp_opt(timestamp as i64, 0)
            .single()
            .map(|dt| dt.format("[%Y-%m-%d %H:%M:%S]").to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let user_agent = request_headers
            .get("user-agent")
            .or_else(|| request_headers.get("User-Agent"))
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let content_type = response_headers
            .get("content-type")
            .or_else(|| response_headers.get("Content-Type"))
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        let duration_micros = start_time.elapsed().as_micros() as u64;
        let duration_ms = duration_micros as f64 / 1000.0;
        let bytes_transferred = request_size + response_size;

        TrafficLog {
            timestamp,
            timestamp_human,
            session_id,
            src_addr,
            dst_addr,
            method,
            url,
            full_url,
            status,
            request_size,
            response_size,
            duration_micros,
            duration_ms,
            is_https,
            user_agent,
            content_type,
            headers: HashMap::new(),
            request_headers,
            response_headers,
            blocked,
            rule_matched,
            bytes_transferred,
            connection_reused: false,
        }
    }
}

struct Stats {
    total_requests: AtomicU64,
    blocked_requests: AtomicU64,
    active_connections: AtomicUsize,
    https_requests: AtomicU64,
    http_requests: AtomicU64,
    bytes_transferred: AtomicU64,
    avg_response_time: AtomicU64,
    peak_connections: AtomicUsize,
    errors: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Stats {
            total_requests: AtomicU64::new(0),
            blocked_requests: AtomicU64::new(0),
            active_connections: AtomicUsize::new(0),
            https_requests: AtomicU64::new(0),
            http_requests: AtomicU64::new(0),
            bytes_transferred: AtomicU64::new(0),
            avg_response_time: AtomicU64::new(0),
            peak_connections: AtomicUsize::new(0),
            errors: AtomicU64::new(0),
        }
    }

    fn connection_start(&self) {
        let current = self.active_connections.fetch_add(1, Ordering::Relaxed) + 1;
        loop {
            let peak = self.peak_connections.load(Ordering::Relaxed);
            if current <= peak {
                break;
            }
            match self.peak_connections.compare_exchange_weak(
                peak,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
    }

    fn connection_end(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    fn record_request(&self, duration_micros: u64, bytes: usize, is_https: bool, is_blocked: bool) {
        if is_blocked {
            self.blocked_requests.fetch_add(1, Ordering::Relaxed);
        } else {
            self.total_requests.fetch_add(1, Ordering::Relaxed);
            if is_https {
                self.https_requests.fetch_add(1, Ordering::Relaxed);
            } else {
                self.http_requests.fetch_add(1, Ordering::Relaxed);
            }
        }

        self.bytes_transferred
            .fetch_add(bytes as u64, Ordering::Relaxed);

        let current_avg = self.avg_response_time.load(Ordering::Relaxed);
        let new_avg = if current_avg == 0 {
            duration_micros
        } else {
            (current_avg * 9 + duration_micros) / 10
        };
        self.avg_response_time.store(new_avg, Ordering::Relaxed);
    }

    fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }
}

struct CorkProxy {
    listen_addr: SocketAddr,
    rules: Arc<RwLock<Vec<Rule>>>,
    log_sender: Sender<TrafficLog>,
    stats: Arc<Stats>,
    buffer_size: usize,
    max_threads: usize,
    server_config: Option<Arc<ServerConfig>>,
    client_config: Arc<ClientConfig>,
    log_format: String,
}

impl CorkProxy {
    fn new(
        listen_addr: SocketAddr,
        cert_path: Option<&str>,
        key_path: Option<&str>,
        log_format: String,
    ) -> Self {
        let buffer_size = get_optimal_buffer_size();
        let max_threads = get_optimal_thread_count();
        let batch_size = get_optimal_batch_size();

        let (log_sender, log_receiver) = bounded(batch_size * 20);

        let log_format_clone = log_format.clone();
        thread::spawn(move || {
            Self::log_writer_thread(log_receiver, batch_size, log_format_clone);
        });

        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));

        let client_config = ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let server_config = if let (Some(cert), Some(key)) = (cert_path, key_path) {
            Self::load_server_config(cert, key)
        } else {
            None
        };

        CorkProxy {
            listen_addr,
            rules: Arc::new(RwLock::new(Vec::new())),
            log_sender,
            stats: Arc::new(Stats::new()),
            buffer_size,
            max_threads,
            server_config,
            client_config: Arc::new(client_config),
            log_format,
        }
    }

    fn load_server_config(cert_path: &str, key_path: &str) -> Option<Arc<ServerConfig>> {
        let cert_file = std::fs::File::open(cert_path).ok()?;
        let key_file = std::fs::File::open(key_path).ok()?;

        let cert_chain = certs(&mut BufReader::new(cert_file))
            .ok()?
            .into_iter()
            .map(Certificate)
            .collect();

        let mut keys: Vec<PrivateKey> = pkcs8_private_keys(&mut BufReader::new(key_file))
            .ok()?
            .into_iter()
            .map(PrivateKey)
            .collect();

        if keys.is_empty() {
            return None;
        }

        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, keys.remove(0))
            .ok()?;

        Some(Arc::new(config))
    }

    fn start(&self) {
        let listener = TcpListener::bind(self.listen_addr).expect("Failed to bind");

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let fd = listener.as_raw_fd();
                let optval: libc::c_int = 1;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEADDR,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                );
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_REUSEPORT,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                );
            }
        }

        let https_support = if self.server_config.is_some() {
            "with HTTPS MITM"
        } else {
            "HTTPS tunnel only"
        };

        println!(
            "Listening on {} with {} threads ({})",
            self.listen_addr, self.max_threads, https_support
        );
        println!(
            "Buffer size: {}KB | Batch size: {}",
            self.buffer_size / 1024,
            get_optimal_batch_size()
        );
        println!("Log format: {}\n", self.log_format);

        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_threads));

        for stream in listener.incoming() {
            match stream {
                Ok(stream) => {
                    let rules = Arc::clone(&self.rules);
                    let log_sender = self.log_sender.clone();
                    let stats = Arc::clone(&self.stats);
                    let permit = semaphore.clone();
                    let buffer_size = self.buffer_size;
                    let server_config = self.server_config.clone();
                    let client_config = Arc::clone(&self.client_config);

                    thread::spawn(move || {
                        if let Ok(_permit) = permit.try_acquire() {
                            stats.connection_start();

                            let session_id = format!(
                                "{:x}",
                                std::time::SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_nanos()
                                    & 0xffffff
                            );

                            Self::handle_connection(
                                stream,
                                session_id,
                                rules,
                                log_sender,
                                stats.clone(),
                                buffer_size,
                                server_config,
                                client_config,
                            );
                            stats.connection_end();
                        } else {
                            stats.record_error();
                        }
                    });
                }
                Err(_) => {
                    self.stats.record_error();
                    continue;
                }
            }
        }
    }

    fn handle_connection(
        mut stream: TcpStream,
        session_id: String,
        rules: Arc<RwLock<Vec<Rule>>>,
        log_sender: Sender<TrafficLog>,
        stats: Arc<Stats>,
        buffer_size: usize,
        server_config: Option<Arc<ServerConfig>>,
        client_config: Arc<ClientConfig>,
    ) {
        let start_time = Instant::now();
        let peer_addr = stream
            .peer_addr()
            .ok()
            .map(|a| a.to_string())
            .unwrap_or_else(|| "unknown".to_string());

        stream.set_read_timeout(Some(READ_TIMEOUT)).ok();
        stream.set_write_timeout(Some(WRITE_TIMEOUT)).ok();
        stream.set_nodelay(true).ok();

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let fd = stream.as_raw_fd();
                let optval: libc::c_int = 1;
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_KEEPALIVE,
                    &optval as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&optval) as libc::socklen_t,
                );
            }
        }

        let mut buffer = vec![0u8; buffer_size];

        match stream.read(&mut buffer) {
            Ok(bytes_read) if bytes_read > 0 => {
                let request = String::from_utf8_lossy(&buffer[..bytes_read]);

                if request.starts_with("CONNECT") {
                    Self::handle_connect_method(
                        &mut stream,
                        &request,
                        session_id,
                        peer_addr,
                        rules,
                        log_sender,
                        stats,
                        start_time,
                        server_config,
                        client_config,
                    );
                } else if Self::is_http_method(&request) {
                    Self::handle_http_request(
                        &mut stream,
                        &request,
                        session_id,
                        peer_addr,
                        rules,
                        log_sender,
                        stats,
                        start_time,
                        buffer_size,
                        false,
                    );
                }
            }
            _ => {
                stats.record_error();
                return;
            }
        }
    }

    fn is_http_method(request: &str) -> bool {
        matches!(
            &request[..4.min(request.len())],
            "GET " | "POST" | "PUT " | "DELE" | "HEAD" | "OPTI" | "PATC" | "TRAC" | "PROF" | "PROP"
        )
    }

    fn parse_headers(lines: &[&str]) -> HashMap<String, String> {
        let mut headers = HashMap::new();

        for line in &lines[1..] {
            if line.is_empty() {
                break;
            }

            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }

        headers
    }

    fn handle_connect_method(
        stream: &mut TcpStream,
        request: &str,
        session_id: String,
        peer_addr: String,
        rules: Arc<RwLock<Vec<Rule>>>,
        log_sender: Sender<TrafficLog>,
        stats: Arc<Stats>,
        start_time: Instant,
        server_config: Option<Arc<ServerConfig>>,
        client_config: Arc<ClientConfig>,
    ) {
        let lines: Vec<&str> = request.lines().collect();
        let original_target = lines
            .get(0)
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default();

        if original_target.is_empty() {
            stats.record_error();
            return;
        }

        let request_headers = Self::parse_headers(&lines);
        let full_url = format!("https://{}", original_target);

        let (_, blocked) = Self::apply_rules(&rules, request);

        if blocked {
            let response = b"HTTP/1.1 403 Forbidden";
            stream.write_all(response).ok();

            let log_entry = TrafficLog::new(
                session_id,
                peer_addr,
                original_target.to_string(),
                "CONNECT".to_string(),
                original_target.to_string(),
                full_url,
                403,
                request.len(),
                response.len(),
                start_time,
                true,
                request_headers,
                HashMap::new(),
                true,
                Some("block_rule".to_string()),
            );

            log_sender.try_send(log_entry).ok();
            stats.record_request(
                start_time.elapsed().as_micros() as u64,
                request.len() + response.len(),
                true,
                true,
            );
            return;
        }

        let target_with_port = if !original_target.contains(':') {
            format!("{}:443", original_target)
        } else {
            original_target.to_string()
        };

        match TcpStream::connect(&target_with_port) {
            Ok(target_stream) => {
                let response = b"HTTP/1.1 200 Connection established\r\n\r\n";
                if stream.write_all(response).is_err() {
                    println!("Failed to send 200 response");
                    stats.record_error();
                    return;
                }
                stream.flush().ok();

                if let Some(server_config) = server_config {
                    Self::handle_https_mitm(
                        stream,
                        &target_with_port,
                        session_id,
                        peer_addr,
                        rules,
                        log_sender,
                        stats,
                        start_time,
                        server_config,
                        client_config,
                    );
                    return;
                }

                let bytes_transferred = Self::tunnel_data(stream, target_stream);
                println!("Tunnel closed. Bytes transferred: {}", bytes_transferred);

                let log_entry = TrafficLog::new(
                    session_id,
                    peer_addr,
                    original_target.to_string(),
                    "CONNECT".to_string(),
                    original_target.to_string(),
                    format!("https://{}", original_target),
                    200,
                    bytes_transferred / 2,
                    bytes_transferred / 2,
                    start_time,
                    true,
                    request_headers,
                    HashMap::new(),
                    false,
                    None,
                );

                log_sender.try_send(log_entry).ok();
                stats.record_request(
                    start_time.elapsed().as_micros() as u64,
                    bytes_transferred,
                    true,
                    false,
                );
            }
            Err(e) => {
                println!("Failed to connect to {}: {}", target_with_port, e);
                let response = b"HTTP/1.1 502 Bad Gateway\r\n\r\nConnection failed";
                stream.write_all(response).ok();
                stats.record_error();
            }
        }
    }

    fn tunnel_data(client_stream: &mut TcpStream, target_stream: TcpStream) -> usize {
        let mut client_clone = client_stream.try_clone().unwrap();
        let mut target_clone = target_stream.try_clone().unwrap();
        let bytes_transferred = Arc::new(AtomicUsize::new(0));
        let bytes_ref = Arc::clone(&bytes_transferred);

        let client_to_target = thread::spawn(move || {
            let mut buf = [0u8; 32768];
            while let Ok(n) = client_clone.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if target_clone.write_all(&buf[..n]).is_err() {
                    break;
                }
                bytes_ref.fetch_add(n, Ordering::Relaxed);
            }
        });

        let mut target_stream = target_stream;
        let mut buf = [0u8; 32768];
        while let Ok(n) = target_stream.read(&mut buf) {
            if n == 0 {
                break;
            }
            if client_stream.write_all(&buf[..n]).is_err() {
                break;
            }
            bytes_transferred.fetch_add(n, Ordering::Relaxed);
        }

        client_to_target.join().ok();
        bytes_transferred.load(Ordering::Relaxed)
    }

    fn handle_https_mitm(
        stream: &mut TcpStream,
        target: &str,
        session_id: String,
        peer_addr: String,
        rules: Arc<RwLock<Vec<Rule>>>,
        log_sender: Sender<TrafficLog>,
        stats: Arc<Stats>,
        start_time: Instant,
        server_config: Arc<ServerConfig>,
        client_config: Arc<ClientConfig>,
    ) {
        use rustls::{ClientConnection, ServerConnection};

        let mut server_conn = match ServerConnection::new(server_config) {
            Ok(conn) => conn,
            Err(_) => {
                stats.record_error();
                return;
            }
        };

        let mut server_stream = rustls::Stream::new(&mut server_conn, stream);
        let mut buffer = vec![0u8; 16384];

        if let Ok(n) = server_stream.read(&mut buffer) {
            let request = String::from_utf8_lossy(&buffer[..n]);
            let lines: Vec<&str> = request.lines().collect();
            let request_headers = Self::parse_headers(&lines);

            let host = Self::extract_host(&lines);
            let (_, blocked) = Self::apply_rules(&rules, &request);
            let rule_matched = if blocked {
                Some("block_rule".to_string())
            } else {
                None
            };

            if blocked {
                let response = b"HTTP/1.1 403 Forbidden";
                let _ = server_stream.write_all(response);

                let log_entry = TrafficLog::new(
                    session_id,
                    peer_addr,
                    host.clone(),
                    "GET".to_string(),
                    target.to_string(),
                    format!("https://{}", target),
                    403,
                    request.len(),
                    response.len(),
                    start_time,
                    true,
                    request_headers,
                    HashMap::new(),
                    true,
                    rule_matched,
                );

                log_sender.try_send(log_entry).ok();
                stats.record_request(
                    start_time.elapsed().as_micros() as u64,
                    request.len() + response.len(),
                    true,
                    true,
                );
                return;
            }

            if let Ok(mut target_stream) = TcpStream::connect(target) {
                let server_name = match target.split(':').next().unwrap_or(target).try_into() {
                    Ok(name) => name,
                    Err(_) => {
                        stats.record_error();
                        return;
                    }
                };

                let mut client_conn = match ClientConnection::new(client_config, server_name) {
                    Ok(conn) => conn,
                    Err(_) => {
                        stats.record_error();
                        return;
                    }
                };

                let mut client_stream = rustls::Stream::new(&mut client_conn, &mut target_stream);

                if client_stream.write_all(request.as_bytes()).is_ok() {
                    let mut response = Vec::new();
                    let mut buf = vec![0u8; 16384];

                    while let Ok(n) = client_stream.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        response.extend_from_slice(&buf[..n]);
                        if response.len() > MAX_RESPONSE_SIZE {
                            break;
                        }
                    }

                    let response_str = String::from_utf8_lossy(&response);
                    let response_lines: Vec<&str> = response_str.lines().collect();
                    let response_headers = Self::parse_headers(&response_lines);
                    let status = Self::extract_status_code(&response_str);

                    let _ = server_stream.write_all(&response);

                    let method = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().next())
                        .unwrap_or("GET")
                        .to_string();

                    let url = request
                        .lines()
                        .next()
                        .and_then(|line| line.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();

                    let log_entry = TrafficLog::new(
                        session_id,
                        peer_addr,
                        host,
                        method,
                        url.clone(),
                        format!("https://{}{}", target, url),
                        status,
                        request.len(),
                        response.len(),
                        start_time,
                        true,
                        request_headers,
                        response_headers,
                        false,
                        None,
                    );

                    log_sender.try_send(log_entry).ok();
                    stats.record_request(
                        start_time.elapsed().as_micros() as u64,
                        request.len() + response.len(),
                        true,
                        false,
                    );
                }
            } else {
                stats.record_error();
            }
        } else {
            stats.record_error();
        }
    }

    fn handle_http_request(
        stream: &mut TcpStream,
        request: &str,
        session_id: String,
        peer_addr: String,
        rules: Arc<RwLock<Vec<Rule>>>,
        log_sender: Sender<TrafficLog>,
        stats: Arc<Stats>,
        start_time: Instant,
        buffer_size: usize,
        is_https: bool,
    ) {
        let lines: Vec<&str> = request.lines().collect();
        let request_line = lines.get(0).unwrap_or(&"");
        let parts: Vec<&str> = request_line.split_whitespace().collect();

        if parts.len() < 3 {
            stats.record_error();
            return;
        }

        let method = parts[0].to_string();
        let url = parts[1].to_string();
        let request_headers = Self::parse_headers(&lines);
        let host = Self::extract_host(&lines);

        if host.is_empty() {
            stats.record_error();
            return;
        }

        let full_url = if is_https {
            format!("https://{}{}", host, url)
        } else {
            format!("http://{}{}", host, url)
        };

        let (_, blocked) = Self::apply_rules(&rules, request);
        let rule_matched = if blocked {
            Some("block_rule".to_string())
        } else {
            None
        };

        if blocked {
            let response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\n\r\nBlocked";
            stream.write_all(response).ok();

            let log_entry = TrafficLog::new(
                session_id,
                peer_addr,
                host,
                method,
                url,
                full_url,
                403,
                request.len(),
                response.len(),
                start_time,
                is_https,
                request_headers,
                HashMap::new(),
                true,
                rule_matched,
            );

            log_sender.try_send(log_entry).ok();
            stats.record_request(
                start_time.elapsed().as_micros() as u64,
                request.len() + response.len(),
                is_https,
                true,
            );
            return;
        }

        let target_addr = if host.contains(':') {
            host.clone()
        } else {
            format!("{}:{}", host, if is_https { 443 } else { 80 })
        };

        if let Ok(mut target_stream) = TcpStream::connect(&target_addr) {
            target_stream.set_nodelay(true).ok();
            target_stream.set_read_timeout(Some(READ_TIMEOUT)).ok();
            target_stream.set_write_timeout(Some(WRITE_TIMEOUT)).ok();

            if target_stream.write_all(request.as_bytes()).is_ok() {
                target_stream.flush().ok();

                let mut response = Vec::with_capacity(buffer_size);
                let mut buf = vec![0u8; buffer_size];
                let mut total_read = 0;

                while let Ok(n) = target_stream.read(&mut buf) {
                    if n == 0 {
                        break;
                    }
                    response.extend_from_slice(&buf[..n]);
                    total_read += n;

                    if total_read > MAX_RESPONSE_SIZE {
                        break;
                    }

                    if let Ok(response_str) = std::str::from_utf8(&response) {
                        if response_str.contains("\r\n\r\n") {
                            if let Some(content_length) = Self::extract_content_length(response_str)
                            {
                                let header_end = response_str.find("\r\n\r\n").unwrap_or(0) + 4;
                                let body_length = response.len() - header_end;
                                if body_length >= content_length {
                                    break;
                                }
                            } else if response_str.contains("Transfer-Encoding: chunked") {
                                if response_str.ends_with("0\r\n\r\n") {
                                    break;
                                }
                            }
                        }
                    }
                }

                let response_str = String::from_utf8_lossy(&response);
                let response_lines: Vec<&str> = response_str.lines().collect();
                let response_headers = Self::parse_headers(&response_lines);
                let status = Self::extract_status_code(&response_str);

                stream.write_all(&response).ok();

                let log_entry = TrafficLog::new(
                    session_id,
                    peer_addr,
                    host,
                    method,
                    url,
                    full_url,
                    status,
                    request.len(),
                    response.len(),
                    start_time,
                    is_https,
                    request_headers,
                    response_headers,
                    false,
                    None,
                );

                log_sender.try_send(log_entry).ok();
                stats.record_request(
                    start_time.elapsed().as_micros() as u64,
                    request.len() + response.len(),
                    is_https,
                    false,
                );
            } else {
                stats.record_error();
            }
        } else {
            stats.record_error();
        }
    }

    fn extract_content_length(response: &str) -> Option<usize> {
        for line in response.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("content-length:") {
                return line[15..].trim().parse().ok();
            }
        }
        None
    }

    fn extract_host(lines: &[&str]) -> String {
        for line in &lines[1..] {
            if line.is_empty() {
                break;
            }
            let lower = line.to_lowercase();
            if lower.starts_with("host:") {
                return line[5..].trim().to_string();
            }
        }
        String::new()
    }

    fn extract_status_code(response: &str) -> u16 {
        response
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or(200)
    }

    fn apply_rules(rules: &Arc<RwLock<Vec<Rule>>>, content: &str) -> (String, bool) {
        let rules_guard = match rules.read() {
            Ok(guard) => guard,
            Err(e) => {
                eprintln!("Failed to acquire rules lock: {}", e);
                return (content.to_string(), false);
            }
        };

        if rules_guard.is_empty() {
            return (content.to_string(), false);
        }

        let mut blocked = false;

        for rule in &*rules_guard {
            if rule.matches(content) {
                match rule.action.as_str() {
                    "block" => {
                        println!("BLOCKING request due to rule: {}", rule.name);
                        blocked = true;
                        break;
                    }
                    _ => {
                        println!("Unknown action '{}' for rule: {}", rule.action, rule.name);
                    }
                }
            }
        }

        (content.to_string(), blocked)
    }

    fn log_writer_thread(
        log_receiver: Receiver<TrafficLog>,
        batch_size: usize,
        log_format: String,
    ) {
        let mut batch = Vec::with_capacity(batch_size);
        let mut last_flush = Instant::now();

        while let Ok(log) = log_receiver.recv() {
            batch.push(log);

            if batch.len() >= batch_size || last_flush.elapsed() >= LOG_FLUSH_INTERVAL {
                Self::flush_logs(&batch, &log_format);
                batch.clear();
                last_flush = Instant::now();
            }
        }

        if !batch.is_empty() {
            Self::flush_logs(&batch, &log_format);
            batch.clear();
        }
    }

    fn flush_logs(logs: &[TrafficLog], log_format: &str) {
        match log_format {
            "json" => Self::flush_logs_json(logs),
            "csv" => Self::flush_logs_csv(logs),
            _ => Self::flush_logs_text(logs),
        }
    }

    fn flush_logs_text(logs: &[TrafficLog]) {
        let mut file = match OpenOptions::new()
            .create(true)
            .append(true)
            .open("cork.log")
        {
            Ok(f) => Some(BufWriter::new(f)),
            Err(_) => None,
        };
        for log in logs {
            let protocol = if log.is_https { "HTTPS" } else { "HTTP" };
            let blocked_str = if log.blocked { "BLOCKED " } else { "" };
            println!(
                "{} {}{} {} {} {} -> {}",
                log.timestamp_human,
                blocked_str,
                log.status,
                log.method,
                log.url,
                log.src_addr,
                log.dst_addr
            );
            if let Some(writer) = file.as_mut() {
                let ua_file = if log.user_agent.len() > 50 {
                    &log.user_agent[..50]
                } else {
                    &log.user_agent
                };
                let _ = write!(
                    writer,
                    "{} {} [{}] {} {} -> {} {} {} {}B->{}B {:.2}ms {} {}\n",
                    log.timestamp_human,
                    log.status,
                    log.session_id,
                    blocked_str.trim(),
                    log.src_addr,
                    log.dst_addr,
                    log.method,
                    log.full_url,
                    log.request_size,
                    log.response_size,
                    log.duration_ms,
                    protocol,
                    ua_file
                );
            }
        }
        if let Some(mut w) = file {
            let _ = w.flush();
        }
    }

    fn flush_logs_json(logs: &[TrafficLog]) {
        if let Ok(file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("cork.jsonl")
        {
            let mut writer = BufWriter::new(file);
            for log in logs {
                if let Ok(json) = serde_json::to_string(log) {
                    writeln!(writer, "{}", json).ok();
                }
            }
            writer.flush().ok();
        }
    }

    fn flush_logs_csv(logs: &[TrafficLog]) {
        let file_exists = std::path::Path::new("cork.csv").exists();

        if let Ok(file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open("cork.csv")
        {
            let mut writer = BufWriter::new(file);

            if !file_exists {
                let header = "timestamp,timestamp_human,session_id,src_addr,dst_addr,method,url,full_url,status,request_size,response_size,duration_ms,is_https,user_agent,content_type,blocked,rule_matched,bytes_transferred\n";
                let _ = writer.write_all(header.as_bytes());
            }
            for log in logs {
                let line = format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{:.2},{},{},{},{},{},{}\n",
                    log.timestamp,
                    log.timestamp_human,
                    log.session_id,
                    log.src_addr,
                    log.dst_addr,
                    log.method,
                    log.url.replace(',', "%2C"),
                    log.full_url.replace(',', "%2C"),
                    log.status,
                    log.request_size,
                    log.response_size,
                    log.duration_ms,
                    log.is_https,
                    log.user_agent.replace(',', "%2C"),
                    log.content_type.replace(',', "%2C"),
                    log.blocked,
                    log.rule_matched.as_deref().unwrap_or(""),
                    log.bytes_transferred
                );
                let _ = writer.write_all(line.as_bytes());
            }
            writer.flush().ok();
        }
    }

    fn load_rules(&self, file_path: &str) {
        if let Ok(content) = std::fs::read_to_string(file_path) {
            if let Ok(mut rules) = serde_json::from_str::<Vec<Rule>>(&content) {
                let mut compiled_count = 0;
                for rule in &mut rules {
                    match rule.compile() {
                        Ok(_) => {
                            compiled_count += 1;
                        }
                        Err(e) => {
                            eprintln!("Failed to compile rule '{}': {}", rule.name, e);
                        }
                    }
                }

                if let Ok(mut guard) = self.rules.write() {
                    *guard = rules
                        .into_iter()
                        .filter(|r| r.compiled_regex.is_some())
                        .collect();
                    println!(
                        "Loaded {} valid rules ({} compiled successfully)",
                        guard.len(),
                        compiled_count
                    );
                }
            } else {
                eprintln!("Failed to parse rules JSON file");
            }
        } else {
            eprintln!("Failed to read rules file: {}", file_path);
        }
    }
}

fn main() {
    println!();
    println!("Running Cork...");
    println!();

    let matches = App::new("Cork")
        .version("1.0")
        .about("Lightweight, powerful HTTP/HTTPS traffic analysis tool for network monitoring")
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .takes_value(true)
                .default_value("8080")
                .help("Listen port"),
        )
        .arg(
            Arg::with_name("host")
                .short("h")
                .long("host")
                .takes_value(true)
                .default_value("127.0.0.1")
                .help("Listen host"),
        )
        .arg(
            Arg::with_name("rules")
                .short("r")
                .long("rules")
                .takes_value(true)
                .help("Rules JSON file path"),
        )
        .arg(
            Arg::with_name("cert")
                .short("c")
                .long("cert")
                .takes_value(true)
                .help("TLS certificate file for HTTPS MITM"),
        )
        .arg(
            Arg::with_name("key")
                .short("k")
                .long("key")
                .takes_value(true)
                .help("TLS private key file for HTTPS MITM"),
        )
        .arg(
            Arg::with_name("log-format")
                .short("f")
                .long("log-format")
                .takes_value(true)
                .possible_values(&["text", "json", "csv"])
                .default_value("text")
                .help("Log output format"),
        )
        .get_matches();

    let host = matches.value_of("host").unwrap();
    let port: u16 = matches
        .value_of("port")
        .unwrap()
        .parse()
        .expect("Invalid port");
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Invalid address");
    let log_format = matches.value_of("log-format").unwrap().to_string();

    let cert_path = matches.value_of("cert");
    let key_path = matches.value_of("key");

    if cert_path.is_some() != key_path.is_some() {
        eprintln!("Both --cert and --key must be provided for HTTPS MITM support");
        std::process::exit(1);
    }

    let proxy = CorkProxy::new(addr, cert_path, key_path, log_format);

    if let Some(rules_file) = matches.value_of("rules") {
        proxy.load_rules(rules_file);
    }

    let log_sender = std::sync::Arc::new(proxy.log_sender.clone());
    ctrlc::set_handler({
        let log_sender = log_sender.clone();
        move || {
            drop(log_sender.clone());
            println!("Shutdown signal received, starting graceful shutdown...");
            std::process::exit(0);
        }
    })
    .expect("Error setting signal handler");

    proxy.start();
}
