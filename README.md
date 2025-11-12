# **PerfLens**

**AI-Powered eBPF Performance Monitoring & Root Cause Analysis for Linux**

PerfLens is a production-ready observability tool that captures slow I/O operations, analyzes system bottlenecks, and provides AI-generated recommendations—all through an interactive terminal interface.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org/)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)
[![Build and publish](https://github.com/devansh-srv/vomit/actions/workflows/publish.yml/badge.svg)](https://github.com/devansh-srv/vomit/actions/workflows/publish.yml)
![GitHub stars](https://img.shields.io/github/stars/devansh-srv/vomit?style=social)

---

## Features

- **Real-time Performance Monitoring**: Track slow I/O operations (read, write, disk I/O) with sub-millisecond precision
- **Stack Trace Capture**: Capture and resolve both kernel and user-space stack traces with symbol resolution
- **Process Correlation**: Track fork/exec chains and build process relationship trees
- **Timeline Analysis**: Visualize event patterns with per-second histograms and time-based correlation
- **AI-Powered Analysis**: Automatic root cause detection using HuggingFace LLM API (Qwen 2.5 72B)
- **Interactive TUI**: Multi-view terminal interface with real-time updates

---

## Technologies

### Core Stack
- **Rust** - High-performance systems programming
- **eBPF** - Kernel-level tracing with zero overhead
- **libbpf-rs** - Rust bindings for libbpf
- **C** - BPF programs for kernel instrumentation

### Tracing & Instrumentation
- **kprobes** - Dynamic kernel function tracing (`vfs_read`, `vfs_write`)
- **tracepoints** - Static trace points (`sched_process_fork`, `sched_process_exec`, `block_rq_*`)
- **BPF Ring Buffers** - Lock-free event streaming from kernel to userspace
- **BPF Stack Maps** - Efficient stack trace capture and storage

### UI & Visualization
- **Ratatui** - Terminal UI framework
- **Crossterm** - Cross-platform terminal manipulation

### AI Integration
- **HuggingFace Router API** - LLM-based analysis
- **Tokio** - Async runtime for API calls
- **Reqwest** - HTTP client with TLS
- **Governor** - Rate limiting

### Symbol Resolution
- **kallsyms** - Kernel symbol table parsing
- **procfs** - Process memory mapping analysis

---

## Prerequisites

### System Requirements
- **Linux kernel 5.8+** with BTF support
- **Root access** (required for eBPF)
- **Rust 1.70+**
- **LLVM/Clang 11+** (for BPF compilation)
- **Linux headers** for your kernel version

### Install Dependencies

#### Ubuntu/Debian
```
sudo apt update
sudo apt install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    pkg-config
```

#### Fedora/RHEL
```
sudo dnf install -y \
    clang \
    llvm \
    elfutils-libelf-devel \
    kernel-devel \
    pkg-config
```

#### Arch Linux
```
sudo pacman -S clang llvm libelf linux-headers
```

---

## Building

### 1. Install Rust (if not already installed)
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 2. Clone Repository
```
git clone https://github.com/yourusername/perflens.git
cd perflens
```

### 3. Build
```
# Debug build
cargo build

# Release build (recommended)
cargo build --release
```

The binary will be at:
- Debug: `target/debug/perflens`
- Release: `target/release/perflens`

---

## Running

### Basic Usage (Without AI)

```
sudo ./target/release/perflens
```

### With AI Analysis

1. **Get HuggingFace API Token**
   - Go to https://huggingface.co/settings/tokens
   - Create a new token with "Read" permission

2. **Set Environment Variable & Run**
   ```
   export HF_TOKEN="hf_xxxxxxxxxxxxxxxxxxxxx"
   sudo -E ./target/release/perflens
   ```

   **Note:** The `-E` flag preserves environment variables when using sudo.

---

## Usage

### TUI Navigation

| Key | Action |
|-----|--------|
| `q` | Quit / Back to dashboard |
| `t` | Timeline view |
| `p` | Process tree view |
| `s` / `Enter` | Stack trace view (select process first) |
| `a` | AI Analysis view |
| `↑` / `↓` | Scroll content |

### Generating Test Load

To see PerfLens in action, generate some I/O activity:

```
# In another terminal
dd if=/dev/zero of=/tmp/test bs=1M count=500

# Or continuous load
while true; do
    dd if=/dev/urandom of=/tmp/test bs=1M count=10 2>/dev/null
    sleep 2
done
```

---

## 🔬 Technical Details

### Architecture

```
┌─────────────────────────────────────────────────┐
│                   PerfLens                      │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌──────────────┐  ┌──────────────┐             │
│  │ BPF Programs │  │  Ring Buffer │             │
│  │  (Kernel)    │──▶│  (Lockless)  │           │
│  └──────────────┘  └──────┬───────┘             │
│         │                  │                    │
│    ┌────┴──────────────────┴────┐               │
│    │   Event Collector Thread    │              │
│    │   (polls ring buffer)       │              │
│    └────────────┬─────────────────┘             │
│                 │                               │
│    ┌────────────▼─────────────┐                 │
│    │   Stats Aggregation      │                 │
│    │   Timeline/Correlation   │                 │
│    └────────────┬─────────────┘                 │
│                 │                               │
│    ┌────────────▼─────────────┐                 │
│    │      TUI Renderer        │                 │
│    │  (Dashboard, Timeline,   │                 │
│    │   Process Tree, etc.)    │                 │
│    └──────────────────────────┘                 │
│                                                 │
│    ┌──────────────────────────┐                 │
│    │  LLM Analyzer Thread     │                 │
│    │  (async, every 30s)      │                 │
│    └──────────────────────────┘                 │
│                                                 │
└─────────────────────────────────────────────────┘
```

### eBPF Programs

- **`trace_read_enter/exit`**: Captures `vfs_read` latency
- **`trace_write_enter/exit`**: Captures `vfs_write` latency
- **`block_io_start/end`**: Captures block device I/O latency
- **`trace_fork`**: Tracks process fork events
- **`trace_exec`**: Tracks process exec events

### Data Collection

- **Event Threshold**: 5ms (configurable)
- **Ring Buffer Size**: 16MB
- **Stack Depth**: 20 frames
- **Timeline Window**: 5 minutes
- **Process Tree**: Tracks parent-child relationships
- **Symbol Resolution**: Real-time using `/proc/kallsyms` and `/proc/[pid]/maps`

### AI Analysis

- **Trigger**: Every 30 seconds (if events exist)
- **Rate Limit**: 10 requests/minute
- **Model**: Qwen 2.5 72B Instruct
- **Input**: System metrics, slow operations, process relationships
- **Output**: Bottleneck summary, root causes, actionable recommendations

---

## Example Output

### Dashboard View
```
┌─ Summary ────────────────────┐  ┌─ Slowest Processes ──────────┐
│ Total slow operations: 42    │  │ postgres (PID 1234) - 45ms   │
│                              │  │ chrome (PID 5678) - 32ms     │
│ By Type:                     │  │ nginx (PID 910) - 28ms       │
│   read: 28                   │  │                              │
│   write: 10                  │  │                              │
│   disk_io: 4                 │  │                              │
└──────────────────────────────┘  └──────────────────────────────┘
┌─ AI Insights ────────────────────────────────────────────────────┐
│ Latest AI Analysis (13:45:22)                                    │
│                                                                  │
│ High disk I/O latency affecting database operations. PostgreSQL  │
│ queries blocked on filesystem reads due to disk queue saturation.│
│                                                                  │
│ 3 issues identified | Press 'a' for details                      │
└──────────────────────────────────────────────────────────────────┘
```

### AI Analysis View
```
AI Performance Analysis

Analysis #3 (13:45:22)

Summary:
The system shows high disk I/O latency affecting database operations.
PostgreSQL is experiencing 45ms read delays, likely due to disk queue
saturation from competing processes.

Issues Detected:
  Disk I/O operations taking 3x longer than baseline
  PostgreSQL queries blocked on filesystem reads
  Multiple processes competing for disk bandwidth

Recommendations:
  Check disk IOPS limits - consider upgrading storage tier
  Implement I/O priority (ionice) for database processes
  Add caching layer to reduce disk read frequency
  Review query patterns for optimization opportunities
```

---

##  Troubleshooting

### "Permission denied" errors
**Solution:** Run with `sudo` - eBPF requires root privileges.

### "Failed to load BPF programs"
**Cause:** Kernel doesn't support BTF or missing headers.
**Solution:**
```
# Check BTF support
ls /sys/kernel/btf/vmlinux

# If missing, enable BTF in kernel config or use BTF-less build
```

### "HF_TOKEN not set" but token is exported
**Cause:** Environment variables not passed to sudo.
**Solution:** Use `sudo -E` flag:
```
export HF_TOKEN="hf_xxx"
sudo -E ./target/release/perflens
```

### AI analysis not running
**Checks:**
1. Verify token is set: `sudo -E printenv | grep HF_TOKEN`
2. Ensure events are being captured (generate I/O load)
3. Wait 30 seconds after first event capture
4. Check logs for "Requesting LLM analysis..."

### No events captured
**Cause:** No slow operations detected (threshold: 5ms).
**Solution:** Generate load:
```
dd if=/dev/zero of=/tmp/test bs=1M count=100
```

---

## Development

### Project Structure
```
perflens/
├── src/
│   ├── bpf/
│   │   └── monitor.bpf.c      # eBPF programs
│   ├── main.rs                # Entry point
│   ├── collector.rs           # Event collection & stats
│   ├── timeline.rs            # Event correlation
│   ├── stacktrace.rs          # Symbol resolution
│   ├── tui.rs                 # Terminal UI
│   ├── analysis.rs            # AI analysis state
│   └── llm/
│       ├── mod.rs
│       ├── client.rs          # HuggingFace client
│       └── prompt.rs          # Prompt builder
├── build.rs                   # BPF compilation
└── Cargo.toml
```

### Build System
- `build.rs` uses `libbpf-cargo` to compile BPF programs
- Generates `monitor.skel.rs` with skeleton bindings
- BPF bytecode embedded in final binary

---

## Contributing

Contributions welcome! Areas for improvement:
- Add more tracepoints (network, memory, locks)
- Implement data export (JSON, Prometheus)
- Add filtering by PID/process name
- Support custom analysis prompts
- Web UI alternative to TUI

---

## License

GPL-3.0 - See [LICENSE](LICENSE) file

---

## Acknowledgments

- **libbpf-rs** team for excellent Rust bindings
- **Ratatui** contributors for the TUI framework
- **HuggingFace** for LLM API access
- Linux kernel developers for eBPF infrastructure

---

## References

- [eBPF Documentation](https://ebpf.io/)
- [libbpf-rs Guide](https://github.com/libbpf/libbpf-rs)
- [BPF Performance Tools](http://www.brendangregg.com/bpf-performance-tools-book.html)
