# Salsa – Encrypted Tunnel

A secure encrypted tunnel built around **Deimos Cipher**. This repository contains server and client components, a Tunnel Manager, and a GUI to start/stop services and monitor traffic.

---

## Project Title

**Salsa – Encrypted Tunnel** — Encrypted tunnel using Deimos Cipher (Python + C++ backend)

## Short Description

Salsa is a lightweight, research-grade encrypted tunnel using the **Deimos Cipher** for transport encryption. It includes a server, client, tunnel manager, and GUI for live traffic monitoring.

## Features

* Authenticated encryption using Deimos Cipher (Python wrapper for C++ DLL)
* Server and client CLI with configuration file support
* Tunnel manager for multiple connections and routing
* GUI for starting/stopping servers and monitoring traffic
* Example configuration and scripts included
* Cross-platform Python + C++ integration

## Security Warning

**Do NOT** expose this software to the public internet without a security audit. This repository is for learning and internal research purposes. For production, use well-audited protocols.

## Getting Started

1. Clone the repository:

```bash
git clone https://github.com/MohsinCell/Salsa-Encrypted-Tunnel.git
cd src
```

2. Create a virtual environment and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```
3. Start the GUI:

```bash
python gui_manager.py
```

## Development Notes

* Keep the Deimos implementation in `src/deimos_wrapper.py` and the C++ DLLs for compatibility.
* Tests and example scripts should be added for integration verification.
* Use `assets/` for GUI or documentation images.
* Ignore compiled files (`*.dll`, `*.obj`, `*.lib`, `*.exp`) and `__pycache__/` in `.gitignore`.

## Contributing

See `CONTRIBUTING.md` for coding guidelines, tests, and pull request workflow.

## License

MIT License — see `LICENSE` file.

