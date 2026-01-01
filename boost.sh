#!/bin/bash
set -e          # Exit immediately if any command fails
set -o pipefail # Catch errors in piped commands

# =================================================================
# MX LINUX FLUXBOX - GOLD MASTER (v8.4 - EXTENDED CLEANUP)
# -----------------------------------------------------------------
# TARGET: Dual Core | 4GB RAM | HDD | SysVinit
# -----------------------------------------------------------------
# CHANGES in v8.4:
# - ADDED: Force removal of broken printer-driver-cups-pdf.
# - ADDED: Aggressive purging of VPN, Printing, VM Tools, & Bloatware.
# - ADDED: Removal of MX-Tour, MX-Welcome, Conky, and Samba.
# - UPDATED: Localepurge configuration and execution.
# - UPDATED: Explicit service enabling for ZRAM/EarlyOOM.
# =================================================================

# --- 0. LOGGING SETUP ---
LOG_FILE="/var/log/mx_optimization_v8.4_$(date +%Y%m%d_%H%M%S).log"
touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO] $(date +'%T') $1${NC}"; }
log_warn() { echo -e "${YELLOW}[WARN] $(date +'%T') $1${NC}"; }
log_error() { echo -e "${RED}[ERROR] $(date +'%T') $1${NC}"; }
log_section() { 
    echo -e "\n${CYAN}============================================================"
    echo -e " STEP: $1"
    echo -e "============================================================${NC}" 
}

error_handler() {
    # Ensure we clean up the lock if the script crashes
    [ -f /usr/sbin/policy-rc.d ] && rm -f /usr/sbin/policy-rc.d
    log_error "Script failed at line $1. Check $LOG_FILE."
    exit 1
}
trap 'error_handler $LINENO' ERR

# --- CONFIGURATION ---
KEYBOARD_LAYOUT="it"
# Note: Adding Italian to localepurge to match keyboard layout, plus English as requested
LOCALES_TO_KEEP="en, en_US, en_US.UTF-8, it, it_IT, it_IT.UTF-8"
GRUB_TIMEOUT_VAL=0

# --- 1. PRE-FLIGHT CHECKS ---
log_section "Pre-Flight Checks"

if [ "$EUID" -ne 0 ]; then
  log_error "Please run as root (sudo bash ./install.sh)."
  exit 1
fi

if [ -n "$SUDO_USER" ]; then
    TARGET_USER="$SUDO_USER"
else
    log_error "Cannot detect actual user. Run with sudo."
    exit 1
fi

USER_HOME=$(getent passwd "$TARGET_USER" | cut -d: -f6)
log_info "Target User: $TARGET_USER"
log_info "Home Dir:    $USER_HOME"
log_info "Log File:    $LOG_FILE"

echo ""
log_warn "SAFE MODE ACTIVE: Services locked to prevent logout."
echo "Press ENTER to start..."
read -r

# --- 2. SERVICE LOCK (ANTI-LOGOUT) ---
log_section "1/16 Locking Services"
# This prevents APT from restarting LightDM/DBus and killing the session
echo "#!/bin/sh" > /usr/sbin/policy-rc.d
echo "exit 101" >> /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d
log_info "Service restarts blocked."

# --- 3. FIX BROKEN PACKAGES (NEW) ---
log_section "2/16 Fixing Broken Packages"
# Specific fix requested for printer-driver-cups-pdf
log_info "Force removing printer-driver-cups-pdf to clear locks..."
echo '#!/bin/sh' | tee /var/lib/dpkg/info/printer-driver-cups-pdf.prerm
echo '#!/bin/sh' | tee /var/lib/dpkg/info/printer-driver-cups-pdf.postrm
chmod +x /var/lib/dpkg/info/printer-driver-cups-pdf.prerm
chmod +x /var/lib/dpkg/info/printer-driver-cups-pdf.postrm
dpkg --remove --force-remove-reinstreq printer-driver-cups-pdf || true
log_info "Broken package fix applied."

# --- 4. DEPENDENCIES ---
log_section "3/16 Dependencies & Config"
apt update

if ! dpkg -s debconf-utils >/dev/null 2>&1; then
    apt install -y debconf-utils
fi

# Updated Localepurge config based on request
if ! dpkg -s localepurge >/dev/null 2>&1; then
    echo "localepurge localepurge/nopurge multiselect $LOCALES_TO_KEEP" | debconf-set-selections
    echo "localepurge localepurge/use-dpkg-feature boolean true" | debconf-set-selections
    echo "localepurge localepurge/summary boolean true" | debconf-set-selections
    echo "localepurge localepurge/verbose boolean false" | debconf-set-selections
fi

# --- 5. INSTALLATION ---
log_section "4/16 Installing Utilities"
log_warn "ACTION REQUIRED: Confirm installation."

apt install --no-install-recommends \
    nodm lxpolkit ufw p7zip-full unrar-free zip unzip \
    ffmpeg libavcodec-extra intel-microcode amd64-microcode \
    localepurge earlyoom preload

# --- 6. PROTECT PACKAGES ---
log_section "5/16 Protecting MX Apps"
log_info "Marking essential MX apps as manual..."
apt-mark manual mx-apps-fluxbox mx-fluxbox mx-updater cleanup-notifier-mx

# --- 7. NODM CONFIG ---
log_section "6/16 Configuring NODM"
NODM_FILE="/etc/default/nodm"
if [ -f "$NODM_FILE" ]; then
    sed -i 's/^NODM_ENABLED=.*/NODM_ENABLED=true/' "$NODM_FILE"
    sed -i "s/^NODM_USER=.*/NODM_USER=$TARGET_USER/" "$NODM_FILE"
    log_info "NODM configured."
else
    log_error "NODM config not found!"
fi

# --- 8. DM SWITCH ---
log_section "7/16 Switching Display Manager"
if [ -x "/etc/init.d/lightdm" ]; then
    update-rc.d lightdm disable || true
    log_info "LightDM disabled."
fi
if [ -x "/etc/init.d/nodm" ]; then
    update-rc.d nodm enable || true
    log_info "NODM enabled."
fi

# --- 9. SERVICE MANAGEMENT ---
log_section "8/16 Disabling Services"
SERVICES=(
    cups cups-browsed bluetooth speech-dispatcher 
    plymouth cryptdisks cryptdisks-early 
    rsyslog uuidd smbd nmbd avahi-daemon 
    rpcbind nfs-common chrony exim4 saned
)
for service in "${SERVICES[@]}"; do
    if [ -x "/etc/init.d/$service" ]; then
        update-rc.d "$service" disable 2>/dev/null || true
        log_info "Disabled service: $service"
    fi
done

# --- 10. REMOVING BLOAT (EXTENDED) ---
log_section "9/16 Removing Bloat"
log_info "Purging requested packages..."

# 1. Printing & Drivers
apt purge -y printer-driver-* cups* system-config-printer* || true

# 2. Networking / VPN / Dial-up
apt purge -y network-manager-openvpn network-manager-pptp network-manager-vpnc \
             openconnect openvpn ppp wvdial mobile-broadband-provider-info \
             telnet ftp whois sendemail || true

# 3. Virtualization & Fingerprint
apt purge -y open-vm-tools fprintd || true

# 4. Utilities & Media Tools
apt purge -y mc galculator sysbench samba smbclient python3-smbc \
             xorriso dvd+rw-tools libburn4t64 genisoimage growisofs \
             cdparanoia vcdimager djvulibre-bin mtools pacpl \
             guvcview bluez-obexd testdisk nwipe gtkhash || true

# 5. Desktop & UI Bloat (Conky, Clipman, etc)
apt purge -y conky-all mx-conky xfce4-clipman clipman \
             xdg-desktop-portal xdg-desktop-portal-gtk modemmanager \
             orca magnus onboard speech-dispatcher xfburn hplip \
             sane-utils blueman bluez flatpak baobab catfish \
             libsane1 mugshot || true

# 6. MX Specific (Tour/Welcome) - NOW PURGING as requested
apt purge -y mx-tour mx-welcome mx-welcome-data || true

# 7. Mail & Keyrings
apt purge -y exim4-base exim4-config gnome-keyring gnome-keyring-pkcs11 libpam-gnome-keyring || true

log_info "Cleaning residual configs..."
dpkg --purge $(dpkg -l | grep "^rc" | awk '{print $2}') 2>/dev/null || true

# --- 11. UNLOCK SERVICES ---
log_section "10/16 Unlocking Services"
rm -f /usr/sbin/policy-rc.d
log_info "Service restarts unblocked."

# --- 12. KERNEL & HDD TWEAKS ---
log_section "11/16 System Tuning"
# Suppress errors if NMI watchdog is locked
cat <<EOF > /etc/sysctl.d/99-minimal.conf
vm.swappiness=100
vm.vfs_cache_pressure=50
kernel.nmi_watchdog=0
net.ipv6.conf.all.disable_ipv6 = 1
EOF
sysctl --system >/dev/null || true

cat <<EOF > /etc/udev/rules.d/60-hdd-scheduler.rules
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="bfq"
EOF

log_info "Optimizing fstab..."
[ ! -f "/etc/fstab.bak.orig" ] && cp "/etc/fstab" "/etc/fstab.bak.orig"
sed -i 's/errors=remount-ro/noatime,nodiratime,commit=60,errors=remount-ro/' /etc/fstab

# Tmpfs
if ! grep -q "tmpfs /tmp" /etc/fstab; then
    echo "tmpfs /tmp tmpfs defaults,noatime,mode=1777,size=256M 0 0" >> /etc/fstab
fi
if ! grep -q "tmpfs /var/log" /etc/fstab; then
    echo "tmpfs /var/log tmpfs defaults,noatime,mode=0755,size=128M 0 0" >> /etc/fstab
fi

# --- 13. ZRAM & EARLYOOM ---
log_section "12/16 Memory Config"
if [ -f /etc/default/zramswap ]; then
    sed -i 's/^PERCENT=.*/PERCENT=60/' /etc/default/zramswap
fi
if [ -f /etc/default/earlyoom ]; then
    sed -i 's/^EARLYOOM_ARGS=.*/EARLYOOM_ARGS="-m 5 -s 5 --avoid ^(Xorg|nodm|fluxbox)$"/' /etc/default/earlyoom
fi

# Enable Memory Services (New Request)
log_info "Enabling Memory Services..."
service zramswap start || true
update-rc.d zramswap enable || true
update-rc.d zramswap defaults || true

service earlyoom start || true
update-rc.d earlyoom enable || true

# --- 14. ACCESSIBILITY & TTY ---
log_section "13/16 Disabling Accessibility"
TARGETS=("/usr/libexec/at-spi-bus-launcher" "/usr/libexec/at-spi2-registryd" "/etc/xdg/autostart/at-spi-dbus-bus.desktop")
for target in "${TARGETS[@]}"; do
    if [ -f "$target" ]; then
        dpkg-divert --add --rename --divert "$target.disabled" "$target"
    fi
done

cp /etc/inittab /etc/inittab.bak.$(date +%s)
sed -i 's/^[3-6]:23:respawn:/#&/' /etc/inittab

CURRENT_HOSTNAME=$(hostname)
if ! grep -q "127.0.1.1.*$CURRENT_HOSTNAME" /etc/hosts; then
    echo "127.0.1.1 $CURRENT_HOSTNAME" >> /etc/hosts
fi

# --- 15. FIREFOX ---
log_section "14/16 Firefox Optimization"
FF_DIR="$USER_HOME/.mozilla/firefox"
if [ -d "$FF_DIR" ]; then
    find "$FF_DIR" -maxdepth 1 -type d -name "*.default*" | while read -r PROFILE_DIR; do
        log_info "Optimizing: $(basename "$PROFILE_DIR")"
        USER_JS="$PROFILE_DIR/user.js"
        [ -f "$USER_JS" ] && cp "$USER_JS" "${USER_JS}.bak"

        cat <<EOF > "$USER_JS"
// === v8.4 OPTIMIZATIONS ===
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.disk.capacity", 0);
user_pref("browser.cache.memory.enable", true);
user_pref("browser.cache.memory.capacity", -1);
user_pref("browser.sessionstore.interval", 900000);
user_pref("toolkit.cosmeticAnimations.enabled", false);
user_pref("browser.download.animateNotifications", false);
user_pref("general.smoothScroll", false); 
user_pref("media.ffmpeg.vaapi.enabled", true);
user_pref("media.hardware-video-decoding.enabled", true);
user_pref("layers.acceleration.force-enabled", true);
user_pref("browser.tabs.unloadOnLowMemory", true);
user_pref("extensions.pocket.enabled", false);
user_pref("toolkit.telemetry.enabled", false);
EOF
        chown "${TARGET_USER}:${TARGET_USER}" "$USER_JS"
    done
fi

# --- 16. STARTUP SCRIPT ---
log_section "15/16 Startup Script"
STARTUP_FILE="$USER_HOME/.fluxbox/startup"
if [ -f "$STARTUP_FILE" ]; then
    cp "$STARTUP_FILE" "${STARTUP_FILE}.bak.$(date +%s)"
    
    # Disable lines for removed packages
    sed -i 's/^conkystart/#conkystart/g' "$STARTUP_FILE"
    sed -i 's|^/usr/lib/policykit-1-gnome/.*|#&|g' "$STARTUP_FILE"
    sed -i 's/^mx-welcome/#mx-welcome/g' "$STARTUP_FILE"
    sed -i 's/^picom/#picom/g' "$STARTUP_FILE"
    sed -i 's/^compton/#compton/g' "$STARTUP_FILE"
    sed -i 's/^clipman/#clipman/g' "$STARTUP_FILE"

    read -r -d '' OPT_BLOCK << EOM || true
# === GOLD MASTER v8.4 ===
export NO_AT_BRIDGE=1
setxkbmap $KEYBOARD_LAYOUT &
lxpolkit &
# ========================
EOM
    if ! grep -q "GOLD MASTER" "$STARTUP_FILE"; then
        ESCAPED_BLOCK=$(echo "$OPT_BLOCK" | sed ':a;N;$!ba;s/\n/\\n/g')
        sed -i "/exec fluxbox/i $ESCAPED_BLOCK" "$STARTUP_FILE"
        log_info "Startup script updated."
    else
        log_info "Startup optimization already present."
    fi
    chown "${TARGET_USER}:${TARGET_USER}" "$STARTUP_FILE"
fi

# --- 17. FINAL CLEANUP ---
log_section "16/16 Final Cleanup"
GRUB_FILE="/etc/default/grub"
sed -i "s/^GRUB_TIMEOUT=[0-9]*/GRUB_TIMEOUT=$GRUB_TIMEOUT_VAL/" "$GRUB_FILE"
sed -i 's/splash//g' "$GRUB_FILE"
if ! grep -q "fastboot" "$GRUB_FILE"; then
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="fastboot quiet /' "$GRUB_FILE"
fi
update-grub

# Remove residual configs in home
rm -rf "$USER_HOME/.config/conky"
rm -f "$USER_HOME/.config/autostart/conky.desktop"
rm -f "$USER_HOME/.config/autostart/mx-welcome.desktop"
rm -f "$USER_HOME/.config/autostart/mx-tour.desktop"
rm -f "$USER_HOME/.config/autostart/clipman.desktop"

# Clean up dpkg distribution files (New Request)
rm -f /etc/init.d/*.dpkg-distrib

log_info "Running Localepurge..."
dpkg-reconfigure -f noninteractive localepurge
localepurge

log_warn "ACTION REQUIRED: Confirm Auto-Remove."
apt autoremove --purge
apt clean

log_section "OPTIMIZATION COMPLETE (v8.4)"
log_info "Log file: $LOG_FILE"
log_info "Please reboot manually to apply changes."
