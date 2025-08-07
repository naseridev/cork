# Cork - Advanced HTTP/HTTPS Traffic Analysis Proxy

Cork is a lightweight, high-performance HTTP/HTTPS proxy server designed for network traffic analysis, monitoring, and security research. Built in Rust, it provides comprehensive traffic inspection capabilities with optional HTTPS Man-in-the-Middle (MITM) functionality for deep packet analysis.

## Features

### Core Capabilities
- **High Performance**: Multi-threaded architecture with optimized buffer management
- **Protocol Support**: HTTP/1.1 and HTTPS with optional TLS termination
- **Traffic Analysis**: Comprehensive request/response logging and metrics
- **Rule-Based Filtering**: Regex-based content filtering and blocking
- **Multiple Logging Formats**: Text, JSON, and CSV output formats
- **Connection Management**: Intelligent connection pooling and timeout handling

### Advanced Features
- **HTTPS MITM**: Optional TLS interception for encrypted traffic analysis
- **Adaptive Performance**: Automatic optimization based on system resources
- **Real-time Statistics**: Connection metrics and performance monitoring
- **Flexible Configuration**: Command-line interface with extensive options

## Technical Architecture

### Performance Optimizations
Cork implements several performance optimizations:

- **Dynamic Resource Allocation**: Automatically adjusts thread pool size and buffer allocation based on available system resources
- **OS-Specific Tuning**: Platform-specific socket optimizations for Linux, Windows, and macOS
- **Batch Processing**: Efficient log batching to minimize I/O overhead
- **Memory Management**: Intelligent buffer sizing and connection reuse

### Security Considerations
- **Certificate Management**: Support for custom TLS certificates for MITM operations
- **Rule Engine**: Regex-based filtering for content analysis and blocking
- **Connection Limits**: Built-in protection against connection exhaustion attacks

## Installation

### Prerequisites
- Rust 1.70+ with Cargo
- OpenSSL development libraries (for TLS support)

### Dependencies
The project relies on several key Rust crates:
- `rustls`: Modern TLS implementation
- `clap`: Command-line argument parsing
- `crossbeam-channel`: High-performance channel communication
- `regex`: Pattern matching for rule engine
- `serde`: Serialization for configuration and logging
- `chrono`: Timestamp handling

### Build Instructions
```bash
git clone https://github.com/naseridev/cork.git
cd cork
cargo build --release
```

## Usage

### Basic HTTP Proxy
```bash
./cork --host 0.0.0.0 --port 8080
```

### HTTPS MITM Proxy
```bash
./cork --host 0.0.0.0 --port 8080 --cert server.crt --key server.key
```

### Advanced Configuration
```bash
./cork \
  --host 0.0.0.0 \
  --port 8080 \
  --rules rules.json \
  --cert server.crt \
  --key server.key \
  --log-format json 
```

## Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--host` | `-h` | Listen address | `127.0.0.1` |
| `--port` | `-p` | Listen port | `8080` |
| `--rules` | `-r` | Path to rules JSON file | None |
| `--cert` | `-c` | TLS certificate for MITM | None |
| `--key` | `-k` | TLS private key for MITM | None |
| `--log-format` | `-f` | Output format (text/json/csv) | `text` |

## Configuration

### Rules Engine
Cork supports regex-based filtering rules defined in JSON format:

```json
[
  {
    "name": "Block Social Media",
    "pattern": "(facebook|twitter|instagram)\\.com",
    "action": "block",
    "replacement": null
  },
  {
    "name": "Block Malware Domains",
    "pattern": "malicious-domain\\.com",
    "action": "block",
    "replacement": null
  }
]
```

### Rule Properties
- **name**: Human-readable rule identifier
- **pattern**: Regular expression for matching
- **action**: Action to take (`block` currently supported)
- **replacement**: Future feature for content modification

## Logging and Output

### Log Formats

#### Text Format (Default)
```
[2024-01-15 14:30:45] 200 GET /api/data 192.168.1.100 -> example.com
```

#### JSON Format
```json
{
  "timestamp": 1705329045,
  "timestamp_human": "[2024-01-15 14:30:45]",
  "session_id": "a1b2c3",
  "src_addr": "192.168.1.100:45678",
  "dst_addr": "example.com:443",
  "method": "GET",
  "url": "/api/data",
  "full_url": "https://example.com/api/data",
  "status": 200,
  "request_size": 512,
  "response_size": 2048,
  "duration_ms": 145.5,
  "is_https": true,
  "user_agent": "Mozilla/5.0...",
  "blocked": false
}
```

#### CSV Format
Suitable for data analysis with spreadsheet applications or data processing pipelines.

### Output Files
- **Text**: `cork.log`
- **JSON**: `cork.jsonl` (JSON Lines format)
- **CSV**: `cork.csv`

## Performance Tuning

### Automatic Optimization
Cork automatically optimizes performance based on:
- **CPU Count**: Thread pool sizing
- **Available Memory**: Buffer allocation
- **Operating System**: Platform-specific optimizations

### Manual Tuning
For specific use cases, consider:
- **High Traffic**: Increase system file descriptor limits
- **Memory Constraints**: Monitor batch sizes and buffer allocation
- **Network Latency**: Adjust timeout values in source code

## Security and Privacy Considerations

### HTTPS MITM Setup
When using MITM functionality:

1. **Generate Certificate Authority**:
```bash
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 365 -key ca.key -out ca.crt
```

2. **Generate Server Certificate**:
```bash
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
```

3. **Client Configuration**: Install `ca.crt` as trusted root certificate on client systems

### Legal and Ethical Considerations
- Ensure compliance with local privacy laws
- Obtain proper authorization before monitoring network traffic
- Use only for legitimate security research or network administration
- Implement appropriate data retention and access controls

## Research Applications

### Network Security Analysis
- **Malware Communication**: Identify C&C traffic patterns
- **Data Exfiltration**: Monitor unusual outbound data flows
- **Protocol Analysis**: Study HTTP/HTTPS usage patterns

### Performance Research
- **Latency Analysis**: Measure request/response times
- **Bandwidth Utilization**: Track data transfer patterns
- **Caching Effectiveness**: Analyze cache hit/miss ratios

### Academic Use Cases
- **Network Behavior Studies**: Understand application communication patterns
- **Security Research**: Analyze attack vectors and defensive measures
- **Protocol Development**: Test new HTTP extensions or modifications

## Contributing

### Development Setup
1. Fork the repository
2. Create feature branch: `git checkout -b feature/enhancement`
3. Follow Rust coding standards and run `cargo clippy`
4. Add tests for new functionality
5. Submit pull request with detailed description

### Code Structure
- **Main Loop**: Connection handling and thread management
- **Protocol Handlers**: HTTP/HTTPS request processing
- **Rule Engine**: Pattern matching and filtering
- **Logging System**: Multi-format output generation
- **Performance Layer**: System optimization and resource management

## Disclaimer

This tool is intended for legitimate network analysis, security research, and educational purposes. Users are responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse of this software.

