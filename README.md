# 🚀 OS Optimization Scripts

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash)
![PowerShell](https://img.shields.io/badge/Language-PowerShell-149FDA?style=for-the-badge&logo=powershell)
![OS](https://img.shields.io/badge/OS-MX_Linux%20%7C%20Windows_11-blue?style=for-the-badge&logo=linux)
![RAM](https://img.shields.io/badge/Idle_RAM-~200MB-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)

> **Performance optimization scripts for MX Linux (Fluxbox & XFCE) and Windows 11.**
> These scripts aggressively debloat the system, tune kernel/power parameters, and strip unnecessary features to maximize performance on low-spec hardware.

---

## ⚠️ Warning — read first

**These scripts are destructive.** They remove printer drivers, Bluetooth/VPN stacks, accessibility tools and other services to achieve maximum performance. **Back up your data** and **review the removal sections** before running. Use at your own risk.

---

## 📂 Repository layout

```
.
├── mx/
│   ├── fluxbox/
│   │   └── boost.sh      # MX Linux Fluxbox optimizer
│   └── xfce/
│       └── boost.sh      # MX Linux XFCE optimizer (v8.6)
└── win11/
    └── boost.ps1         # Windows 11 optimizer (PowerShell)
```

---

## 🐧 MX Linux Fluxbox Optimizer

Turns a minimal MX Linux install into an ultra-light **Fluxbox** desktop targeting **~200 MB idle RAM**.

**Key features**
- ⚡ **Ultra-low memory** — `zram` compressed swap (≈60% of RAM) + kernel tuning (`vm.swappiness=100`, `vfs_cache_pressure=50`).
- 🚀 **Instant boot** — replaces `lightdm` with `nodm` for auto-login straight into the desktop.
- 🧹 **Aggressive debloat** — purges unused drivers, Bluetooth/VPN, CUPS/printing, accessibility tools, LibreOffice, etc.
- 🦊 **Firefox hardening** — injects a privacy/performance `user.js`.
- 🛠 **System tuning** — `EarlyOOM`, disk-scheduler tuning, `/tmp` and `/var/log` mounted to RAM.

**Run**
```bash
cd mx/fluxbox
chmod +x boost.sh
sudo ./boost.sh
```

---

## 🖥️ MX Linux XFCE Optimizer (v8.6)

Same philosophy, tuned for the **XFCE** desktop environment. Ships with structured, timestamped logging to `/var/log/mx_xfce_optimization_v8.6_*.log`, robust `set -euo pipefail` error handling and idempotent system tweaks.

**Run**
```bash
cd mx/xfce
chmod +x boost.sh
sudo ./boost.sh
```

---

## 💠 Windows 11 Optimizer

Comprehensive debloating and performance tuning for **Windows 11** (requires administrator privileges).

**Key features**
- 🔧 **Trusted tooling integration** — Massgrave, Chris Titus Tech's WinUtil, Win11Debloat.
- 🧹 **Service debloating** — disables Spooler, Fax, DiagTrack (telemetry), Xbox services, SysMain, search indexing, etc.
- ⚡ **Power & visuals** — High Performance power plan, hibernation disabled, transparency/animations off.
- 🎮 **Gaming tweaks** — mouse acceleration disabled for 1:1 input.
- 🛡️ **Privacy** — telemetry blocked, WebExperience/background apps removed.

**Run**
```powershell
cd win11
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\boost.ps1
```

---

## ⚙️ Under the hood

- **Idempotent & logged** — the MX scripts tee all output to a timestamped log in `/var/log/`.
- **Fail-fast** — `set -e` / `set -o pipefail` (MX) and an explicit admin check + self-elevation (Windows).
- **Configurable** — key variables (e.g. `KEYBOARD_LAYOUT`) are declared at the top of each script.

---

## 🤝 Contributing

Found a way to save another 10 MB of RAM or improve Windows performance? Pull requests are welcome!

---

## 📄 License

This project is licensed under the **MIT License**.
