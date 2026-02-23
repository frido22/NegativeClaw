# Contributing

Pull requests welcome. Keep it lean -- every byte counts.

## Setup

```bash
# Linux x86-64
sudo apt install nasm
make

# Or use Docker
docker build -t negativeclaw .
```

## Guidelines

- Pure x86-64 assembly, no libc, no external dependencies
- Test that it assembles and links before submitting (`make clean && make`)
- Keep functions minimal -- if code isn't called, delete it
- Comments: one-line function headers, not novels

## Reporting Issues

Open an issue with:
- What you expected
- What happened
- How to reproduce
