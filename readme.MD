# 🚀 MX Fluxbox Ultimate Optimizer

![Bash](https://img.shields.io/badge/Language-Bash-4EAA25?style=for-the-badge&logo=gnu-bash)
![OS](https://img.shields.io/badge/OS-MX_Linux-blue?style=for-the-badge&logo=linux)
![RAM](https://img.shields.io/badge/Idle_RAM-~200MB-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-orange?style=for-the-badge)

> **Turn MX Linux Fluxbox into a lightweight rocket.** 
> Reduces startup RAM consumption to approximately **200MB** by stripping unnecessary services, optimizing kernel parameters, and removing bloatware.

---

## 📖 About
This script is designed for **MX Linux (Fluxbox Edition)**. It aggressively debloats the system, replaces heavy login managers with `nodm`, optimizes Firefox, and tunes the kernel for low-spec hardware or performance enthusiasts.

**⚠️ Warning:** This script is destructive. It removes printer drivers, Bluetooth, VPN supports, and accessibility tools to achieve maximum performance.

---

## ✨ Key Features

*   **⚡ Ultra-Low Memory Usage:** Uses `zram` and kernel tuning (`vm.swappiness`, `vfs_cache_pressure`) to keep RAM usage ~200MB at boot.
*   **🚀 Instant Boot:** Replaces `lightdm` with `nodm` for instant auto-login and sets Grub timeout to 0.
*   **🧹 Aggressive Debloating:** Purges unused drivers (printers, scanners), accessibility tools, localized fonts, and heavy background services.
*   **🦊 Firefox Hardening:** Inject a custom `user.js` for privacy and performance (disables telemetry, disk cache, and cosmetic animations).
*   **🛠 System Tuning:**
    *   Enables `EarlyOOM` to prevent system freezes.
    *   Optimizes disk schedulers (`bfq` for HDDs).
    *   Mounts `/tmp` and `/var/log` to RAM to save SSD wear.
    *   Cleans up `localepurge` to keep only English/Italian locales (configurable).

---

## 🛠️ Installation & Usage

### 1. Download the Script
Clone this repository or download the script directly.

```bash
git clone https://github.com/yourusername/mx-fluxbox-optimizer.git
cd mx-fluxbox-optimizer
chmod +x optimize.sh
```

### 2. Configure (Optional but Recommended)
Open the script and edit the variables at the top to match your specific needs:

```bash
# Inside the script
KEYBOARD_LAYOUT="it"  # Change to "us", "fr", "de", etc.
LOCALES_TO_KEEP="en, en_US, en_US.UTF-8, it, it_IT..." # Add your language
```

### 3. Run as Root
Execute the script using `sudo`.

```bash
sudo ./optimize.sh
```

> **Note:** The script has an interactive safety pause. Press `ENTER` to begin, and confirm `Y` when `apt` asks for permission to purge packages.

---

## 🗑️ What Gets Removed?
To achieve the 200MB target, the script removes the following categories of software:

| Category | Items Removed |
| :--- | :--- |
| **Connectivity** | Bluetooth (`bluez`), VPNs (`openvpn`, `network-manager-pptp`), Modem Managers |
| **Printing/Scanning** | CUPS, HPLIP, Sane, Scanner drivers |
| **Accessibility** | Orca, Speech Dispatcher, Onboard, Magnus |
| **MX Specifics** | MX-Tour, MX-Welcome, Conky, MX-Docs |
| **Apps** | LibreOffice components, CD Burners (`xfburn`), Thunderbird, unused games |

---

## ⚙️ Under the Hood

### 🖥️ Display Manager
The script disables `LightDM` and installs `nodm`.
*   **Result:** The system boots directly into the Fluxbox desktop without a login screen (Auto-login is forced for the sudo user).

### 🧠 Memory Management
*   **ZRAM:** Creates a compressed swap block in RAM (60% of total RAM).
*   **Sysctl:** 
    *   `vm.swappiness=100` (Aggressively use ZRAM).
    *   `vm.vfs_cache_pressure=50`.
*   **EarlyOOM:** Kills heavy processes if RAM becomes critically low, preferring to kill the browser rather than the X server.

### 🏠 Fluxbox Configuration
*   Backs up your current `~/.fluxbox/startup`.
*   Disables `conky`, `compton`/`picom`, and `clipman`.
*   Injects `lxpolkit` (PolicyKit authentication agent) and keyboard layout settings.

---

## 📝 Configuration Variables

If you want to customize the script before running, look for these variables at the top of the file:

*   `KEYBOARD_LAYOUT`: Sets the X11 keyboard layout (Default: `it`).
*   `LOCALES_TO_KEEP`: Which languages `localepurge` should save (Default: `en` and `it`).
*   `GRUB_TIMEOUT_VAL`: How long the boot menu waits (Default: `0` seconds).

---

## ⚠️ Disclaimer
**Use at your own risk.**
This script is intended for experienced users who want a minimal system.
1.  **Backup your data** before running this.
2.  If you use a printer or Bluetooth mouse, **do not run this script blindly** (or edit the `apt purge` section first).
3.  The script creates a detailed log file at `/var/log/mx_optimization_*.log`.

---

## 🤝 Contributing
Found a way to save another 10MB of RAM? Pull requests are welcome!

1.  Fork the Project
2.  Create your Feature Branch
3.  Commit your Changes
4.  Push to the Branch
5.  Open a Pull Request
