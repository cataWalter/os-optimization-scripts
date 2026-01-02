```
# 🚀 OS Optimization Scripts

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash)
![PowerShell](https://img.shields.io/badge/Language-PowerShell-149FDA?style=for-the-badge&logo=powershell)
![OS](https://img.shields.io/badge/OS-MX_Linux%20%7C%20Windows_11-blue?style=for-the-badge&logo=linux)
![RAM](https://img.shields.io/badge/Idle_RAM-~200MB-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)

> **Ultimate performance optimization scripts for both MX Linux Fluxbox and Windows 11.** 
> These scripts aggressively debloat systems, optimize kernel parameters, and tune settings for maximum performance on low-spec hardware.

---

## 📖 About

This repository contains two powerful optimization scripts designed to transform your operating system into a lightweight, high-performance machine:

1. **MX Linux Fluxbox Optimizer** - Reduces startup RAM consumption to approximately **200MB**
2. **Windows 11 Optimizer** - Comprehensive debloating and performance tuning for Windows 11

Both scripts are designed for users who want maximum performance and are willing to sacrifice unnecessary features for speed.

**⚠️ Warning:** These scripts are destructive. They remove printer drivers, Bluetooth, VPN supports, accessibility tools, and other features to achieve maximum performance.

---

## ✨ Available Optimizers

### 🐧 MX Linux Fluxbox Ultimate Optimizer

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash)
![OS](https://img.shields.io/badge/OS-MX_Linux-blue?style=for-the-badge&logo=linux)

**Key Features:**
*   **⚡ Ultra-Low Memory Usage:** Uses `zram` and kernel tuning to keep RAM usage ~200MB at boot
*   **🚀 Instant Boot:** Replaces `lightdm` with `nodm` for instant auto-login
*   **🧹 Aggressive Debloating:** Purges unused drivers, accessibility tools, and heavy background services
*   **🦊 Firefox Hardening:** Inject custom `user.js` for privacy and performance
*   **🛠 System Tuning:** Enables `EarlyOOM`, optimizes disk schedulers, mounts `/tmp` and `/var/log` to RAM

**Installation:**
```bash
cd mx-fluxbox
chmod +x boost.sh
sudo ./boost.sh
```

**What Gets Removed:**
*   **Connectivity:** Bluetooth, VPNs, Modem Managers
*   **Printing/Scanning:** CUPS, HPLIP, Sane, Scanner drivers
*   **Accessibility:** Orca, Speech Dispatcher, Onboard, Magnus
*   **Apps:** LibreOffice, Thunderbird, unused games, MX-specific tools

[**Full MX Fluxbox Documentation**](#mx-linux-fluxbox-optimizer-details)

---

### 💹 Windows 11 Ultimate Optimizer

![PowerShell](https://img.shields.io/badge/Language-PowerShell-149FDA?style=for-the-badge&logo=powershell)
![OS](https://img.shields.io/badge/OS-Windows_11-blue?style=for-the-badge&logo=windows)

**Key Features:**
*   **🔧 Interactive Tools Integration:** Massgrave, CTT WinUtil, Win11Debloat
*   **🧹 Service Debloating:** Disables background services and telemetry
*   **⚡ Power Optimization:** High Performance power plan, hibernation disabled
*   **🎮 Gaming Tweaks:** Mouse acceleration disabled, transparency effects off
*   **🛡️ Privacy:** Telemetry blocked, WebExperience disabled

**Installation:**
```powershell
cd win11
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\boost.ps1
```

**What Gets Disabled/Removed:**
*   **Services:** Spooler, Fax, DiagTrack, Xbox services, Search indexing, SysMain
*   **Telemetry:** Data collection blocked, TextInputHost disabled
*   **Visual Effects:** Transparency effects disabled for GPU performance
*   **Background Apps:** WebExperience and other background processes removed

[**Full Windows 11 Documentation**](#windows-11-optimizer-details)

---

## 🛠️ Installation & Usage

### MX Linux Fluxbox

1. **Download the Script**
```bash
cd mx-fluxbox
chmod +x boost.sh
```

2. **Configure (Optional)**
Open the script and edit variables at the top:
```bash
KEYBOARD_LAYOUT="it"  # Change to your layout
LOCALES_TO_KEEP="en, en_US, en_US.UTF-8, it..." # Add your languages
```

3. **Run as Root**
```bash
sudo ./boost.sh
```

> **Note:** The script has an interactive safety pause. Press `ENTER` to begin, and confirm `Y` when `apt` asks for permission to purge packages.

### Windows 11

1. **Run as Administrator**
Right-click PowerShell and select "Run as Administrator"

2. **Execute the Script**
```powershell
cd win11
.\boost.ps1
```

3. **Follow Interactive Prompts**
The script will launch several optimization tools that require user interaction

4. **Manual Actions Required**
After the script completes, you'll need to:
*   Disable swap/pagefile (if you have 32GB+ RAM)
*   Install AIM Toolkit for Ramdisk usage
*   Enable XMP/DOCP in BIOS for RAM speed
*   Restart your computer

---

## ⚙️ Under the Hood

### MX Linux Fluxbox Optimizer Details

#### 🖥️ Display Manager
*   Disables `LightDM` and installs `nodm`
*   **Result:** System boots directly into Fluxbox desktop without login screen

#### 🧠 Memory Management
*   **ZRAM:** Creates compressed swap block in RAM (60% of total RAM)
*   **Sysctl:** `vm.swappiness=100`, `vm.vfs_cache_pressure=50`
*   **EarlyOOM:** Kills heavy processes if RAM becomes critically low

#### 🏠 Fluxbox Configuration
*   Disables `conky`, `compton`/`picom`, and `clipman`
*   Injects `lxpolkit` (PolicyKit authentication agent)
*   Sets keyboard layout automatically

### Windows 11 Optimizer Details

#### 🔧 Interactive Tools
*   **Massgrave:** System activation and cleanup
*   **CTT WinUtil:** Chris Titus Tech optimization suite
*   **Win11Debloat:** Comprehensive Windows debloating

#### 🛡️ Privacy & Performance
*   **Telemetry Blocking:** Disables Microsoft data collection
*   **Service Management:** Stops and disables unnecessary background services
*   **Visual Optimization:** Disables transparency and animations for GPU performance

#### ⚡ Power Management
*   **High Performance Plan:** Sets optimal power settings
*   **Hibernation Disabled:** Frees up SSD space equivalent to RAM size
*   **Mouse Precision:** Disables acceleration for 1:1 movement

---

## ⚠️ Important Disclaimers

**Use at your own risk.**

1.  **Backup your data** before running these scripts.
2.  If you use printers, Bluetooth devices, or accessibility tools, **do not run these scripts blindly** (or edit the removal sections first).
3.  The MX Linux script creates a detailed log file at `/var/log/mx_optimization_*.log`.
4.  The Windows script requires administrator privileges and makes system-level changes.
5.  Some optimizations may affect system functionality - review the removed items carefully.

---

## 🤝 Contributing

Found a way to save another 10MB of RAM or improve Windows performance? Pull requests are welcome!

1.  Fork the Project
2.  Create your Feature Branch
3.  Commit your Changes
4.  Push to the Branch
5.  Open a Pull Request

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
