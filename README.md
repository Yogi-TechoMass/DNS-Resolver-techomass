# DNS Resolver – High Performance DNS Resolver in Go

**A lightweight, high-performance DNS resolver implemented in Go, designed for speed, efficiency, and scalability.**

---

## Table of Contents

* [Overview](#overview)
* [Features](#features)
* [Installation](#installation)
* [Usage](#usage)
* [Architecture](#architecture)
* [Configuration](#configuration)
* [Performance](#performance)
* [Contributing](#contributing)
* [License](#license)

---

## Overview

DNS plays a vital role in the internet ecosystem, translating human-readable domain names into IP addresses. The *DNS Resolver* project focuses on delivering fast, scalable, and reliable DNS resolution. Written in Go, it leverages concurrency and optimized caching to handle large volumes of DNS queries efficiently.

---

## Features

* **High Throughput & Low Latency**: Built using Go’s concurrency primitives for fast request handling.
* **Caching Mechanism**: Reduces redundant lookups by storing recent query results.
* **Lightweight Design**: Minimal dependencies and resource footprint, ideal for microservices or containerized environments.
* **Scalable & Concurrent**: Can easily handle multiple simultaneous DNS queries.
* **Pluggable Logging / Monitoring**: Designed for observability and debugging.

---

## Installation

```bash
git clone https://github.com/Yogi-TechoMass/DNS-Resolver-techomass.git
cd DNS-Resolver-techomass
go build -o dns-resolver
```

Ensure Go is installed (version 1.18 or newer is recommended).

---

## Usage

```
go mod tidy
go build -o DNS-Resolver-techoMass
echo "google.com" | ./DNS-Resolver-techomass
```

### Example:
**Type the Following Commands One by One To Run the Tool:**
*-->go mod tidy*//
---
*-->go build -o DNS-Resolver-techoMass*//
---
*-->echo "google.com" | ./DNS-Resolver-techomass*//
---

#### Suggested Options (domain):

* **-cache**: Enable caching of responses
* **-timeout**: Set a timeout duration for queries (e.g., `-timeout=2s`)
* **-server**: Specify a custom DNS server (default: system DNS)
* **-verbose**: Enable verbose logging for troubleshooting



---

## Architecture

The resolver employs several components working in concert:

1. **Client Interface** – Handles incoming DNS queries.
2. **Resolver Core** – Orchestrates query handling and caching logic.
3. **Cache Layer** – Stores responses to minimize lookup latency.
4. **Upstream Resolver Module** – Communicates with authoritative DNS servers.
5. **Response Handler** – Delivers results and logs performance metrics.

```
Client → Resolver Core → Cache → Upstream Resolver
                                ↓
                           Response Handler
```



---

## Configuration

You can configure the resolver using environment variables or command-line flags:

| Variable / Flag | Description                     | Default        |
| --------------- | ------------------------------- | -------------- |
| `-cache`        | Enable in-memory caching        | Off            |
| `-timeout`      | DNS query timeout               | 5s             |
| `-server`       | Upstream DNS server (IP or URL) | System default |
| `-verbose`      | Enable detailed logs            | Off            |

Feel free to tailor these defaults to your environment or use case.

---

## Performance

To validate performance improvements, benchmark the resolver against standard tools like `dig` or `nslookup`:

* Measure **response time per query**, **throughput**, and **resource utilization**.
* Enable caching and test cache *hit rate* and **latency reduction**.



---

## Contributing

Contributions are welcome! Here’s how to get involved:

1. Fork the repository.
2. Create a feature or bugfix branch:

   ```bash
   git checkout -b feature/your-feature-name
   ```
3. Make your changes and add tests if applicable.
4. Commit and push to your fork:

   ```bash
   git commit -m "Add feature: XYZ"
   git push origin feature/your-feature-name
   ```
5. Submit a Pull Request. Make sure your code follows the existing style and includes documentation.

---

## License

This project is open source. Please refer to the `LICENSE` file in the repository for details.

---

Feel free to tweak any sections to better match your codebase or desired tone. Let me know if you'd like help tailoring specific usage flags, integrating code snippets, or adding diagrams!
