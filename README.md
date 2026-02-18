# NegativeClaw

A fun experiment to answer one question: **how small can an AI agent actually be?**

We imagine a future where AI writes machine code directly -- no compilers, no runtimes, just raw instructions for maximum efficiency. This is a first try at that vision: an AI agent written in pure x86-64 assembly, built with the help of AI (Claude), pushing toward the theoretical minimum of what it takes to talk to an LLM.

Inspired by the OpenClaw / ZeroClaw / PicoClaw trend of shrinking AI agents, NegativeClaw takes it to the logical extreme: no libc, no dependencies, direct syscalls only. The entire TLS 1.3 stack, crypto, DNS, HTTP, and JSON parsing -- all hand-written assembly.

```
+-------------------------------------------------------------+
|           NegativeClaw - Target: ~20KB binary               |
+-------------------------------------------------------------+
|  - Pure x86-64 Linux assembly                               |
|  - No libc, no dependencies                                 |
|  - TLS 1.3 with ChaCha20-Poly1305                          |
|  - X25519 key exchange                                      |
|  - Direct Claude API calls                                  |
|  - DNS resolution built-in                                  |
+-------------------------------------------------------------+
```

## Size Comparison

| Project | Language | Binary Size | Lines of Code |
|---------|----------|-------------|---------------|
| **NegativeClaw** | x86-64 ASM | ~20 KB | 4,984 |
| MimiClaw | C (ESP32) | ~100 KB | ? |
| ZeroClaw | Rust | 3.4 MB | ? |
| PicoClaw | Go | ~10 MB | ? |
| OpenClaw | TypeScript | ~100 MB | ? |

## Quick Start

**Requirements**: NASM, GNU ld, Linux x86-64 (or Docker)

```bash
# Install NASM (Ubuntu/Debian)
sudo apt install nasm

# Build
make

# Set your Anthropic API key
export ANTHROPIC_API_KEY="sk-ant-api03-..."

# Run
./negative_claw
```

That's it. No npm install, no cargo build, no virtual environments.

If you're on macOS or Windows, use Docker:

```bash
docker run -it --rm -v $(pwd):/code ubuntu:latest bash
apt update && apt install -y nasm binutils
cd /code && make
export ANTHROPIC_API_KEY="sk-ant-api03-..."
./negative_claw
```

## Architecture

```
src/
|-- main.asm          # Entry point, DNS, HTTP, REPL loop    (1,041 lines)
|-- sha256.asm        # SHA-256 + HMAC + HKDF                  (747 lines)
|-- x25519.asm        # Curve25519 key exchange                 (715 lines)
|-- chacha20poly.asm  # ChaCha20-Poly1305 AEAD cipher          (983 lines)
+-- tls13.asm         # TLS 1.3 handshake & record layer     (1,498 lines)
```

## How It Works

1. **Startup**: Read `ANTHROPIC_API_KEY` from environment, parse /etc/resolv.conf
2. **DNS**: Resolve api.anthropic.com via UDP
3. **Input**: Read user message from stdin
4. **Connect**: TCP socket to port 443
5. **TLS 1.3 Handshake**: X25519 key exchange, full RFC 8446 key schedule
6. **HTTP POST**: Build JSON request to /v1/messages with proper Content-Length
7. **Receive**: Accumulate multi-record TLS response
8. **Parse**: Extract assistant reply from JSON
9. **Loop**: Print response, prompt for next message

### What's Inside

**Crypto** (all from scratch, no libraries):
- SHA-256 (FIPS 180-4), HMAC-SHA256, HKDF-Extract/Expand/Expand-Label
- X25519 elliptic curve Diffie-Hellman (TweetNaCl-style, 16x64-bit limbs)
- ChaCha20 stream cipher + Poly1305 MAC (5x26-bit limb arithmetic)

**TLS 1.3**:
- ClientHello with supported_versions, key_share, signature_algorithms
- Full key schedule: early, handshake, and application secrets
- Encrypted record layer with nonce XOR sequence numbering

**Application**:
- DNS resolver (parses /etc/resolv.conf, falls back to 1.1.1.1)
- HTTP/1.1 with JSON escaping and bounds checking
- Response parser handles both success and API error formats

### Syscalls Used

| Syscall | # | Purpose |
|---------|---|---------|
| read | 0 | stdin, sockets, files |
| write | 1 | stdout, sockets |
| open | 2 | /etc/resolv.conf |
| close | 3 | file descriptors |
| socket | 41 | TCP/UDP |
| connect | 42 | server connection |
| sendto | 44 | DNS queries |
| recvfrom | 45 | DNS responses |
| exit | 60 | exit |
| getrandom | 318 | random bytes |

## Limitations

- **No certificate verification** -- trusts the server (TOFU model)
- **Single connection per message** -- no keep-alive
- **ASCII only** -- no Unicode in JSON
- **No streaming** -- waits for complete response
- **Linux x86-64 only** -- direct syscalls

## Make Targets

```bash
make            # Build
make clean      # Remove build artifacts
make strip      # Strip symbols for smallest binary
make size       # Show section and binary sizes
make disasm     # Generate disassembly
```

## Why?

Because it's fun. And because a fully functional HTTPS client with TLS 1.3 can fit in under 5,000 lines of assembly, producing a binary smaller than most "hello world" programs in modern languages.

## License

MIT

## References

- [TLS 1.3 RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446)
- [The Illustrated TLS 1.3 Connection](https://tls13.xargs.org/)
- [ChaCha20-Poly1305 RFC 7539](https://tools.ietf.org/html/rfc7539)
- [X25519 RFC 7748](https://tools.ietf.org/html/rfc7748)
- [TweetNaCl](https://tweetnacl.cr.yp.to/)
- [HKDF RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
