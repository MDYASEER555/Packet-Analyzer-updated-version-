# DPI Engine - Deep Packet Inspection System


This document explains the project and how to build and run it. Start with the Windows Quick Start below if you just want to launch the dashboard.

---

## Table of Contents

1. [Quick Start (Windows)](#quick-start-windows)
2. [What is DPI?](#1-what-is-dpi)
3. [Networking Background](#2-networking-background)
4. [Project Overview](#3-project-overview)
5. [File Structure](#4-file-structure)
6. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
7. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
8. [Deep Dive: Each Component](#7-deep-dive-each-component)
9. [How SNI Extraction Works](#8-how-sni-extraction-works)
10. [How Blocking Works](#9-how-blocking-works)
11. [Building and Running](#10-building-and-running)
12. [Understanding the Output](#11-understanding-the-output)
13. [Local Web Dashboard (MERN)](#12-local-web-dashboard-mern)

---

## Quick Start (Windows)

This is the recommended way to run the React dashboard, Express API, MongoDB
job history, and C++ DPI engine from PowerShell or the VS Code terminal.

### Requirements

- Node.js 22.12 or newer and npm.
- A working MongoDB Atlas cluster, database user, and an active Network Access
  entry for the public IP of the network you are using.
- The included `dpi_engine.exe`, or build it using the CMake commands below.
- For live capture only: Wireshark with the Npcap capture driver installed.

### 1. Open the project folder

In VS Code choose **File → Open Folder** and open the extracted project folder
(the one containing `package.json`). Open **Terminal → New Terminal**. Confirm
the terminal is at the project root:

```powershell
Get-Location
Test-Path package.json
```

The second command should return `True`.

### 2. Install the Node packages

Run this once for each extracted project copy:

```powershell
npm install
```

### 3. Configure MongoDB and the DPI engine

Create `backend/.env` from the example only if it does not already exist:

```powershell
if (-not (Test-Path backend\.env)) { Copy-Item backend\.env.example backend\.env }
```

Open `backend/.env` and set:

- `MONGO_URI` to the full URI from **Atlas → Connect → Drivers → Node.js**. Use
  the Atlas database user's credentials (not your Atlas website password).
- `DPI_ENGINE_PATH` to the engine executable. If `dpi_engine.exe` is in the
  project root, keep `../dpi_engine.exe`. If CMake placed it in
  `build\Release`, use `../build/Release/dpi_engine.exe` instead.

In Atlas, make sure the cluster is active and the public IP of your current
network is **Active** under **Network Access**. If your IP changes (for example
when switching to a hotspot), add the new current IP. Keep `backend/.env`
private; never commit it or paste the connection string into chat.

If `dpi_engine.exe` is missing, install CMake and a C++17 compiler, then build
from the project root:

```powershell
cmake -S . -B build
cmake --build build --config Release
```

### 4. Start the application

From the project root run:

```powershell
npm run dev
```

The launcher starts the API first and waits until its health endpoint responds
before starting Vite. When Vite reports its local URL, open
<http://127.0.0.1:5173/>. Keep the terminal open while using the app. Press
**Ctrl+C** in that terminal to stop it.

### 5. Analyze a saved PCAP

In the dashboard, select **SAVED PCAP**, choose or drop a classic `.pcap` file
(up to 100 MB by default), set any optional block rules, and click **START
ANALYSIS**. The job appears in **Recent captures**. When it completes, use
**DOWNLOAD FILTERED PCAP** to save the result. The current engine accepts
classic `.pcap`; `.pcapng` must be converted to classic PCAP first.

### 6. Capture traffic live

Install Wireshark and include Npcap during installation. In the dashboard select
**LIVE CAPTURE**, choose the Wi-Fi or Ethernet interface carrying the traffic,
choose a duration, and click **START LIVE CAPTURE**. When the timer ends (or the
upload-size limit is reached), the dashboard saves a PCAP and queues it for the
same DPI analysis. Live capture observes and saves traffic; rule selections
filter the resulting PCAP and do not block traffic on your device or network.
If no Wi-Fi/Ethernet interfaces appear, repair
Npcap and restart the terminal. If needed, set `DUMPCAP_PATH` in `backend/.env`
to the full path to `dumpcap.exe` (commonly
`C:/Program Files/Wireshark/dumpcap.exe`).

### Common startup problems

- **`concurrently` or Vite is not recognized:** run `npm install` at the project
  root, then retry `npm run dev`.
- **MongoDB authentication failed:** verify the Atlas database username and
  password in `MONGO_URI`; percent-encode reserved password characters such as
  `@` when they appear in the URI.
- **Atlas TLS/network error:** confirm the cluster is active and the current
  network IP is Active in Atlas. Try a different network and make sure outbound
  TCP port 27017 is allowed.
- **`CHECK SETUP` in the dashboard:** confirm the API and database are running
  and `DPI_ENGINE_PATH` points to an existing engine executable.

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [DPI Engine] → Filtered Traffic (PCAP)
                           ↓
                    - Identifies apps (YouTube, Facebook, etc.)
                    - Blocks based on rules
                    - Generates reports
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** - headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?** 
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we should block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│ Wireshark   │     │ DPI Engine  │     │ Output      │
│ Capture     │ ──► │             │ ──► │ PCAP        │
│ (input.pcap)│     │ - Parse     │     │ (filtered)  │
└─────────────┘     │ - Classify  │     └─────────────┘
                    │ - Block     │
                    │ - Report    │
                    └─────────────┘
```

### Two Versions

| Version | File | Use Case |
|---------|------|----------|
| Simple (Single-threaded) | `src/main_working.cpp` | Learning, small captures |
| Multi-threaded | `src/dpi_mt.cpp` | Larger offline captures (experimental) |

The C++ engine processes saved Ethernet PCAP files. Its packet parser currently
handles IPv4 with TCP or UDP, including common 802.1Q and QinQ tags; the engine
does not itself capture live traffic or block packets inline on a network interface.
The optional local web dashboard can use Wireshark's `dumpcap` to save a timed
live capture, then submits that saved PCAP to the same offline engine. Ethernet
frames and IPv4 fragments it cannot inspect are copied to
the output unchanged (fail-open). TLS inspection reassembles TCP payload
segments, including out-of-order arrivals, up to 32 KiB per flow to extract
ClientHello SNI. IPv4 lengths bound parsing so Ethernet padding is not treated
as application payload.
The output writer restores original packet order across worker threads, and the
engine refuses to use the same file for input and output. Output open, write, and
flush failures cause the run to return an error.

---

## 4. File Structure

```
packet_analyzer/
├── include/                    # Header files (declarations)
│   ├── pcap_reader.h          # PCAP file reading
│   ├── packet_parser.h        # Network protocol parsing
│   ├── sni_extractor.h        # TLS/HTTP inspection
│   ├── types.h                # Data structures (FiveTuple, AppType, etc.)
│   ├── rule_manager.h         # Blocking rules (multi-threaded version)
│   ├── connection_tracker.h   # Flow tracking (multi-threaded version)
│   ├── load_balancer.h        # LB thread (multi-threaded version)
│   ├── fast_path.h            # FP thread (multi-threaded version)
│   ├── thread_safe_queue.h    # Thread-safe queue
│   └── dpi_engine.h           # Main orchestrator
│
├── src/                        # Implementation files
│   ├── pcap_reader.cpp        # PCAP file handling
│   ├── packet_parser.cpp      # Protocol parsing
│   ├── sni_extractor.cpp      # SNI/Host extraction
│   ├── types.cpp              # Helper functions
│   ├── main_working.cpp       # ★ SIMPLE VERSION ★
│   ├── dpi_mt.cpp             # ★ MULTI-THREADED VERSION ★
│   └── [other files]          # Supporting code
│
├── generate_test_pcap.py      # Creates test data
├── test_dpi.pcap              # Sample capture with various traffic
└── README.md                  # This file!
```

---

## 5. The Journey of a Packet (Simple Version)

Let's trace a single packet through `main_working.cpp`:

### Step 1: Read PCAP File

```cpp
PcapReader reader;
reader.open("capture.pcap");
```

**What happens:**
1. Open the file in binary mode
2. Read the 24-byte global header (magic number, version, etc.)
3. Verify it's a valid PCAP file

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← Read once at start
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← Timestamp, length
│ Packet Data (variable)     │  ← Actual network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
├────────────────────────────┤
│ ... more packets ...       │
└────────────────────────────┘
```

### Step 2: Read Each Packet

```cpp
while (reader.readNextPacket(raw)) {
    // raw.data contains the packet bytes
    // raw.header contains timestamp and length
}
```

**What happens:**
1. Read 16-byte packet header
2. Read N bytes of packet data (N = header.incl_len)
3. Return false when no more packets

### Step 3: Parse Protocol Headers

```cpp
PacketParser::parse(raw, parsed);
```

**What happens (in packet_parser.cpp):**

```
raw.data bytes:
[0-13]   Ethernet Header
[14-33]  IP Header  
[34-53]  TCP Header
[54+]    Payload

After parsing:
parsed.src_mac  = "00:11:22:33:44:55"
parsed.dest_mac = "aa:bb:cc:dd:ee:ff"
parsed.src_ip   = "192.168.1.100"
parsed.dest_ip  = "172.217.14.206"
parsed.src_port = 54321
parsed.dest_port = 443
parsed.protocol = 6 (TCP)
parsed.has_tcp  = true
```

**Parsing the Ethernet Header (14 bytes):**
```
Bytes 0-5:   Destination MAC
Bytes 6-11:  Source MAC
Bytes 12-13: EtherType (0x0800 = IPv4)
```

**Parsing the IP Header (20+ bytes):**
```
Byte 0:      Version (4 bits) + Header Length (4 bits)
Byte 8:      TTL (Time To Live)
Byte 9:      Protocol (6=TCP, 17=UDP)
Bytes 12-15: Source IP
Bytes 16-19: Destination IP
```

**Parsing the TCP Header (20+ bytes):**
```
Bytes 0-1:   Source Port
Bytes 2-3:   Destination Port
Bytes 4-7:   Sequence Number
Bytes 8-11:  Acknowledgment Number
Byte 12:     Data Offset (header length)
Byte 13:     Flags (SYN, ACK, FIN, etc.)
```

### Step 4: Create Five-Tuple and Look Up Flow

```cpp
FiveTuple tuple;
tuple.src_ip = parseIP(parsed.src_ip);
tuple.dst_ip = parseIP(parsed.dest_ip);
tuple.src_port = parsed.src_port;
tuple.dst_port = parsed.dest_port;
tuple.protocol = parsed.protocol;

Flow& flow = flows[tuple];  // Get or create
```

**What happens:**
- The flow table is a hash map: `FiveTuple → Flow`
- If this 5-tuple exists, we get the existing flow
- If not, a new flow is created
- All packets with the same 5-tuple share the same flow

### Step 5: Extract SNI (Deep Packet Inspection)

```cpp
// For HTTPS traffic (port 443)
if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
    auto sni = SNIExtractor::extract(payload, payload_length);
    if (sni) {
        flow.sni = *sni;                    // "www.youtube.com"
        flow.app_type = sniToAppType(*sni); // AppType::YOUTUBE
    }
}
```

**What happens (in sni_extractor.cpp):**

1. **Check if it's a TLS Client Hello:**
   ```
   Byte 0: Content Type = 0x16 (Handshake) ✓
   Byte 5: Handshake Type = 0x01 (Client Hello) ✓
   ```

2. **Navigate to Extensions:**
   ```
   Skip: Version, Random, Session ID, Cipher Suites, Compression
   ```

3. **Find SNI Extension (type 0x0000):**
   ```
   Extension Type: 0x0000 (SNI)
   Extension Length: N
   SNI List Length: M
   SNI Type: 0x00 (hostname)
   SNI Length: L
   SNI Value: "www.youtube.com"  ← FOUND!
   ```

4. **Map SNI to App Type:**
   ```cpp
   // In types.cpp
   if (sni.find("youtube") != std::string::npos) {
       return AppType::YOUTUBE;
   }
   ```

### Step 6: Check Blocking Rules

```cpp
if (rules.isBlocked(tuple.src_ip, flow.app_type, flow.sni)) {
    flow.blocked = true;
}
```

**What happens:**
```cpp
// Check IP blacklist
if (blocked_ips.count(src_ip)) return true;

// Check app blacklist
if (blocked_apps.count(app)) return true;

// Check domain blacklist (substring match)
for (const auto& dom : blocked_domains) {
    if (sni.find(dom) != std::string::npos) return true;
}

return false;
```

### Step 7: Forward or Drop

```cpp
if (flow.blocked) {
    dropped++;
    // Don't write to output
} else {
    forwarded++;
    // Write packet to output file
    output.write(packet_header);
    output.write(packet_data);
}
```

### Step 8: Generate Report

After processing all packets:
```cpp
// Count apps
for (const auto& [tuple, flow] : flows) {
    app_stats[flow.app_type]++;
}

// Print report
"YouTube: 150 packets (15%)"
"Facebook: 80 packets (8%)"
...
```

---

## 6. The Journey of a Packet (Multi-threaded Version)

The multi-threaded version (`dpi_mt.cpp`) adds **parallelism** for high performance:

### Architecture Overview

```
                    ┌─────────────────┐
                    │  Reader Thread  │
                    │  (reads PCAP)   │
                    └────────┬────────┘
                             │
              ┌──────────────┴──────────────┐
              │      hash(5-tuple) % 2      │
              ▼                             ▼
    ┌─────────────────┐           ┌─────────────────┐
    │  LB0 Thread     │           │  LB1 Thread     │
    │  (Load Balancer)│           │  (Load Balancer)│
    └────────┬────────┘           └────────┬────────┘
             │                             │
      ┌──────┴──────┐               ┌──────┴──────┐
      │hash % 2     │               │hash % 2     │
      ▼             ▼               ▼             ▼
┌──────────┐ ┌──────────┐   ┌──────────┐ ┌──────────┐
│FP0 Thread│ │FP1 Thread│   │FP2 Thread│ │FP3 Thread│
│(Fast Path)│ │(Fast Path)│   │(Fast Path)│ │(Fast Path)│
└─────┬────┘ └─────┬────┘   └─────┬────┘ └─────┬────┘
      │            │              │            │
      └────────────┴──────────────┴────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   Output Queue        │
              └───────────┬───────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │  Output Writer Thread │
              │  (writes to PCAP)     │
              └───────────────────────┘
```

### Why This Design?

1. **Load Balancers (LBs):** Distribute work across FPs
2. **Fast Paths (FPs):** Do the actual DPI processing
3. **Consistent Hashing:** Same 5-tuple always goes to same FP

**Why consistent hashing matters:**
```
Connection: 192.168.1.100:54321 → 142.250.185.206:443

Packet 1 (SYN):         hash → FP2
Packet 2 (SYN-ACK):     hash → FP2  (same FP!)
Packet 3 (Client Hello): hash → FP2  (same FP!)
Packet 4 (Data):        hash → FP2  (same FP!)

All packets of this connection go to FP2.
FP2 can track the flow state correctly.
```

### Detailed Flow

#### Step 1: Reader Thread

```cpp
// Main thread reads PCAP
while (reader.readNextPacket(raw)) {
    Packet pkt = createPacket(raw);
    
    // Hash to select Load Balancer
    size_t lb_idx = hash(pkt.tuple) % num_lbs;
    
    // Push to LB's queue
    lbs_[lb_idx]->queue().push(pkt);
}
```

#### Step 2: Load Balancer Thread

```cpp
void LoadBalancer::run() {
    while (running_) {
        // Pop from my input queue
        auto pkt = input_queue_.pop();
        
        // Hash to select Fast Path
        size_t fp_idx = hash(pkt.tuple) % num_fps_;
        
        // Push to FP's queue
        fps_[fp_idx]->queue().push(pkt);
    }
}
```

#### Step 3: Fast Path Thread

```cpp
void FastPath::run() {
    while (running_) {
        // Pop from my input queue
        auto pkt = input_queue_.pop();
        
        // Look up flow (each FP has its own flow table)
        Flow& flow = flows_[pkt.tuple];
        
        // Classify (SNI extraction)
        classifyFlow(pkt, flow);
        
        // Check rules
        if (rules_->isBlocked(pkt.tuple.src_ip, flow.app_type, flow.sni)) {
            stats_->dropped++;
        } else {
            // Forward: push to output queue
            output_queue_->push(pkt);
        }
    }
}
```

#### Step 4: Output Writer Thread

```cpp
void outputThread() {
    while (running_ || output_queue_.size() > 0) {
        auto pkt = output_queue_.pop();
        
        // Write to output file
        output_file.write(packet_header);
        output_file.write(pkt.data);
    }
}
```

### Thread-Safe Queue

The magic that makes multi-threading work:

```cpp
template<typename T>
class TSQueue {
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;
    
    void push(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(item);
        not_empty_.notify_one();  // Wake up waiting consumer
    }
    
    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [&]{ return !queue_.empty(); });
        T item = queue_.front();
        queue_.pop();
        return item;
    }
};
```

**How it works:**
- `push()`: Producer adds item, signals waiting consumers
- `pop()`: Consumer waits until item available, then takes it
- `mutex`: Only one thread can access at a time
- `condition_variable`: Efficient waiting (no busy-loop)

---

## 7. Deep Dive: Each Component

### pcap_reader.h / pcap_reader.cpp

**Purpose:** Read network captures saved by Wireshark

**Key structures:**
```cpp
struct PcapGlobalHeader {
    uint32_t magic_number;   // 0xa1b2c3d4 identifies PCAP
    uint16_t version_major;  // Usually 2
    uint16_t version_minor;  // Usually 4
    uint32_t snaplen;        // Max packet size captured
    uint32_t network;        // 1 = Ethernet
};

struct PcapPacketHeader {
    uint32_t ts_sec;         // Timestamp (seconds)
    uint32_t ts_usec;        // Timestamp (microseconds)
    uint32_t incl_len;       // Bytes saved in file
    uint32_t orig_len;       // Original packet size
};
```

**Key functions:**
- `open(filename)`: Open PCAP, validate header
- `readNextPacket(raw)`: Read next packet into buffer
- `close()`: Clean up

### packet_parser.h / packet_parser.cpp

**Purpose:** Extract protocol fields from raw bytes

**Key function:**
```cpp
bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    parseEthernet(...);  // Extract MACs, EtherType
    parseIPv4(...);      // Extract IPs, protocol, TTL
    parseTCP(...);       // Extract ports, flags, seq numbers
    // OR
    parseUDP(...);       // Extract ports
}
```

**Important concepts:**

*Network Byte Order:* Network protocols use big-endian (most significant byte first). Your computer might use little-endian. We use `ntohs()` and `ntohl()` to convert:
```cpp
// ntohs = Network TO Host Short (16-bit)
uint16_t port = ntohs(*(uint16_t*)(data + offset));

// ntohl = Network TO Host Long (32-bit)
uint32_t seq = ntohl(*(uint32_t*)(data + offset));
```

### sni_extractor.h / sni_extractor.cpp

**Purpose:** Extract domain names from TLS and HTTP

**For TLS (HTTPS):**
```cpp
std::optional<std::string> SNIExtractor::extract(
    const uint8_t* payload, 
    size_t length
) {
    // 1. Verify TLS record header
    // 2. Verify Client Hello handshake
    // 3. Skip to extensions
    // 4. Find SNI extension (type 0x0000)
    // 5. Extract hostname string
}
```

**For HTTP:**
```cpp
std::optional<std::string> HTTPHostExtractor::extract(
    const uint8_t* payload,
    size_t length
) {
    // 1. Verify HTTP request (GET, POST, etc.)
    // 2. Search for "Host: " header
    // 3. Extract value until newline
}
```

### types.h / types.cpp

**Purpose:** Define data structures used throughout

**FiveTuple:**
```cpp
struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    
    bool operator==(const FiveTuple& other) const;
};
```

**AppType:**
```cpp
enum class AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    // ... more apps
};
```

**sniToAppType function:**
```cpp
AppType sniToAppType(const std::string& sni) {
    if (sni.find("youtube") != std::string::npos) 
        return AppType::YOUTUBE;
    if (sni.find("facebook") != std::string::npos) 
        return AppType::FACEBOOK;
    // ... more patterns
}
```

---

## 8. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, everything is       │
     │       encrypted - we can't see it)      │
```

**We can only extract SNI from the Client Hello!**

### TLS Client Hello Structure

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  Version = 0x0301 (TLS 1.0)
Bytes 3-4:  Record Length

-- Handshake Layer --
Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

-- Client Hello Body --
Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length (N)
Bytes 44 to 44+N: Session ID
... Cipher Suites ...
... Compression Methods ...

-- Extensions --
Bytes X-X+1: Extensions Length
For each extension:
    Bytes: Extension Type (2)
    Bytes: Extension Length (2)
    Bytes: Extension Data

-- SNI Extension (Type 0x0000) --
Extension Type: 0x0000
Extension Length: L
  SNI List Length: M
  SNI Type: 0x00 (hostname)
  SNI Length: K
  SNI Value: "www.youtube.com" ← THE GOAL!
```

### Our Extraction Code (Simplified)

```cpp
std::optional<std::string> SNIExtractor::extract(
    const uint8_t* payload, size_t length
) {
    // Check TLS record header
    if (payload[0] != 0x16) return std::nullopt;  // Not handshake
    if (payload[5] != 0x01) return std::nullopt;  // Not Client Hello
    
    size_t offset = 43;  // Skip to session ID
    
    // Skip Session ID
    uint8_t session_len = payload[offset];
    offset += 1 + session_len;
    
    // Skip Cipher Suites
    uint16_t cipher_len = readUint16BE(payload + offset);
    offset += 2 + cipher_len;
    
    // Skip Compression Methods
    uint8_t comp_len = payload[offset];
    offset += 1 + comp_len;
    
    // Read Extensions Length
    uint16_t ext_len = readUint16BE(payload + offset);
    offset += 2;
    
    // Search for SNI extension
    size_t ext_end = offset + ext_len;
    while (offset + 4 <= ext_end) {
        uint16_t ext_type = readUint16BE(payload + offset);
        uint16_t ext_data_len = readUint16BE(payload + offset + 2);
        offset += 4;
        
        if (ext_type == 0x0000) {  // SNI!
            // Parse SNI structure
            uint16_t sni_len = readUint16BE(payload + offset + 3);
            return std::string(
                (char*)(payload + offset + 5), 
                sni_len
            );
        }
        
        offset += ext_data_len;
    }
    
    return std::nullopt;  // SNI not found
}
```

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source |
| App | `YouTube` | All YouTube connections |
| Domain | `tiktok` | Any SNI containing "tiktok" |

### The Blocking Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Is source IP in blocked list?  │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is app type in blocked list?   │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blocked domain? │──Yes──► DROP
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD
```

### Flow-Based Blocking

**Important:** We block at the *flow* level, not packet level.

```
Connection to YouTube:
  Packet 1 (SYN)           → No SNI yet, FORWARD
  Packet 2 (SYN-ACK)       → No SNI yet, FORWARD  
  Packet 3 (ACK)           → No SNI yet, FORWARD
  Packet 4 (Client Hello)  → SNI: www.youtube.com
                           → App: YOUTUBE (blocked!)
                           → Mark flow as BLOCKED
                           → DROP this packet
  Packet 5 (Data)          → Flow is BLOCKED → DROP
  Packet 6 (Data)          → Flow is BLOCKED → DROP
  ...all subsequent packets → DROP
```

**Why this approach?**
- We can't identify the app until we see the Client Hello
- Once identified, we block all future packets of that flow
- The connection will fail/timeout on the client

---

## 10. Building and Running

### Prerequisites

- CMake 3.16 or newer
- A C++17 compiler (GCC, Clang, or MSVC)
- Threads support (provided by the platform C++ runtime)

### Build Commands

**Recommended (CMake):**
```bash
cmake -S . -B build
cmake --build build --config Release
```

This creates four targets: `dpi_engine` (modular multithreaded engine),
`dpi_mt` (standalone multithreaded implementation), `dpi_simple` (learning
implementation), and `packet_analyzer` (header viewer). On multi-configuration
generators such as Visual Studio, executables are placed under `build/Release`.

Run the regression checks with:
```bash
ctest --test-dir build --build-config Release --output-on-failure
```

**Direct build of the modular engine with GCC/Clang:**
```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/main_dpi.cpp src/dpi_engine.cpp src/connection_tracker.cpp \
    src/fast_path.cpp src/load_balancer.cpp src/rule_manager.cpp \
    src/pcap_reader.cpp src/packet_parser.cpp src/sni_extractor.cpp src/types.cpp
```

**Simple Version:**
```bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

**Standalone multithreaded version:**
```bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

### Running

**Basic usage:**
```bash
chcp 65001
./dpi_engine test_dpi.pcap output.pcap
```

**With blocking:**
```bash
./dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook \
    --block-port 443
    chcp 65001
    ./dpi_engine test_dpi.pcap output.pcap\ --block-app YouTube \ --block-app TikTok \ --block-ip 192.168.1.50 \ --block-domain facebook 
```

**Configure threads (multi-threaded only):**
```bash
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4
# Creates 4 LB threads × 4 FP threads = 16 processing threads
```

### Creating Test Data

```bash
python3 generate_test_pcap.py
# Creates test_dpi.pcap with sample traffic
```

---

## 11. Understanding the Output

### Sample Output

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Total Bytes:                5738                              ║
║ TCP Packets:                  73                              ║
║ UDP Packets:                   4                              ║
╠══════════════════════════════════════════════════════════════╣
║ Forwarded:                    69                              ║
║ Dropped:                       8                              ║
╠══════════════════════════════════════════════════════════════╣
║ THREAD STATISTICS                                             ║
║   LB0 dispatched:             53                              ║
║   LB1 dispatched:             24                              ║
║   FP0 processed:              53                              ║
║   FP1 processed:               0                              ║
║   FP2 processed:               0                              ║
║   FP3 processed:              24                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6% ##########                     ║
║ Unknown              16  20.8% ####                           ║
║ YouTube               4   5.2% # (BLOCKED)                    ║
║ DNS                   4   5.2% #                              ║
║ Facebook              3   3.9%                                ║
║ ...                                                           ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - github.com -> GitHub
  ...
```

### What Each Section Means

| Section | Meaning |
|---------|---------|
| Configuration | Number of threads created |
| Rules | Which blocking rules are active |
| Total Packets | Packets read from input file |
| Forwarded | Packets written to output file |
| Dropped | Packets blocked (not written) |
| Thread Statistics | Work distribution across threads |
| Application Breakdown | Traffic classification results |
| Detected SNIs | Actual domain names found |

---

## 12. Extending the Project

### Ideas for Improvement

1. **Add More App Signatures**
   ```cpp
   // In types.cpp
   if (sni.find("twitch") != std::string::npos)
       return AppType::TWITCH;
   ```

2. **Add Bandwidth Throttling**
   ```cpp
   // Instead of DROP, delay packets
   if (shouldThrottle(flow)) {
       std::this_thread::sleep_for(10ms);
   }
   ```

3. **Add Live Statistics Dashboard**
   ```cpp
   // Separate thread printing stats every second
   void statsThread() {
       while (running) {
           printStats();
           sleep(1);
       }
   }
   ```

4. **Implement full QUIC/HTTP3 inspection**
   - QUIC Initial packets require header protection removal, Initial-key derivation,
     and CRYPTO-frame reassembly before the TLS ClientHello can be inspected.

5. **Add Persistent Rules**
   - Save rules to file
   - Load on startup

---

## Summary

This DPI engine demonstrates:

1. **Network Protocol Parsing** - Understanding packet structure
2. **Deep Packet Inspection** - Looking inside encrypted connections
3. **Flow Tracking** - Managing stateful connections
4. **Multi-threaded Architecture** - Scaling with thread pools
5. **Producer-Consumer Pattern** - Thread-safe queues

The key insight is that even HTTPS traffic leaks the destination domain in the TLS handshake, allowing network operators to identify and control application usage.

---

## Questions?

If you have questions about any part of this project, the code is well-commented and follows the same flow described in this document. Start with the simple version (`main_working.cpp`) to understand the concepts, then move to the multi-threaded version (`dpi_mt.cpp`) to see how parallelism is added.

---

## 12. Local Web Dashboard (MERN)

The optional dashboard adds a React interface, an Express API, and MongoDB job
history around the existing C++ engine. Saved PCAP files and timed live captures
are processed by the local engine; the API is bound to `127.0.0.1` by default. Only classic `.pcap` files
are accepted, up to 100 MB by default. The dashboard can apply app, domain, IP,
and destination-port rules to the analysis output, then download the filtered
capture when processing finishes. The engine CLI also accepts `--block-port
<0-65535>` for filtering PCAP output.

For live capture on Windows, install Wireshark and its Npcap capture driver.
The dashboard lists local interfaces using Wireshark's `dumpcap`; capture runs
for a selected duration (15 seconds to 15 minutes), then saves a classic PCAP
and queues it for analysis. It also stops when the configured upload-size limit
is reached. Live capture requires permission to access the selected adapter;
if `dumpcap` is not found on `PATH`, set `DUMPCAP_PATH` in `backend/.env` to its
full path (commonly `C:/Program Files/Wireshark/dumpcap.exe`). Live capture is
passive; only the resulting PCAP is filtered by the DPI rules.

### Running the dashboard

Follow the [Windows Quick Start](#quick-start-windows) at the top of this
README. It covers Atlas setup, environment variables, dependencies, engine
configuration, and running both the API and web client. The API defaults to
`http://127.0.0.1:4000`; the web client opens at `http://127.0.0.1:5173/`.

The dashboard uses a single background worker by default. Adjust `MAX_WORKERS`,
`MAX_UPLOAD_MB`, and `ENGINE_TIMEOUT_MS` in `backend/.env` to tune local job
limits. Keep `HOST` set to `127.0.0.1` for a local-only instance; this starter
dashboard does not include user accounts or remote-access authentication.


