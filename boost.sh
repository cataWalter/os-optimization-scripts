#!/bin/bash
set -e          # Exit immediately if any command fails
set -o pipefail # Catch errors in piped commands

# =================================================================
# MX LINUX FLUXBOX - GOLD MASTER (v8.3 - STABLE FIX)
# -----------------------------------------------------------------
# TARGET: Dual Core | 4GB RAM | HDD | SysVinit
# -----------------------------------------------------------------
# FIXES in v8.3:
# - FIXED: 'sed' syntax error in Startup Script (Line 265 crash).
# - FIXED: Sysctl warnings on restricted kernels.
# - CONFIRMED: Anti-Logout mechanism works (Logs verified).
# =================================================================

# --- 0. LOGGING SETUP ---
LOG_FILE="/var/log/mx_optimization_v8.3_$(date +%Y%m%d_%H%M%S).log"
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
log_section "1/15 Locking Services"
# This prevents APT from restarting LightDM/DBus and killing the session
echo "#!/bin/sh" > /usr/sbin/policy-rc.d
echo "exit 101" >> /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d
log_info "Service restarts blocked."

# --- 3. DEPENDENCIES ---
log_section "2/15 Dependencies"
apt update
if ! dpkg -s debconf-utils >/dev/null 2>&1; then
    apt install -y debconf-utils
fi
if ! dpkg -s localepurge >/dev/null 2>&1; then
    echo "localepurge localepurge/nopurge multiselect en_US.UTF-8, it_IT.UTF-8" | debconf-set-selections
    echo "localepurge localepurge/use-dpkg-feature boolean true" | debconf-set-selections
fi

# --- 4. INSTALLATION ---
log_section "3/15 Installing Utilities"
log_warn "ACTION REQUIRED: Confirm installation."

apt install --no-install-recommends \
    nodm lxpolkit ufw p7zip-full unrar-free zip unzip \
    ffmpeg libavcodec-extra intel-microcode amd64-microcode \
    localepurge earlyoom preload

# --- 5. PROTECT PACKAGES ---
log_section "4/15 Protecting MX Apps"
log_info "Marking MX apps as manual..."
apt-mark manual mx-apps-fluxbox mx-fluxbox mx-updater cleanup-notifier-mx

# --- 6. NODM CONFIG ---
log_section "5/15 Configuring NODM"
NODM_FILE="/etc/default/nodm"
if [ -f "$NODM_FILE" ]; then
    sed -i 's/^NODM_ENABLED=.*/NODM_ENABLED=true/' "$NODM_FILE"
    sed -i "s/^NODM_USER=.*/NODM_USER=$TARGET_USER/" "$NODM_FILE"
    log_info "NODM configured."
else
    log_error "NODM config not found!"
fi

# --- 7. DM SWITCH ---
log_section "6/15 Switching Display Manager"
if [ -x "/etc/init.d/lightdm" ]; then
    update-rc.d lightdm disable || true
    log_info "LightDM disabled."
fi
if [ -x "/etc/init.d/nodm" ]; then
    update-rc.d nodm enable || true
    log_info "NODM enabled."
fi

# --- 8. SERVICE MANAGEMENT ---
log_section "7/15 Disabling Services"
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

# --- 9. REMOVING BLOAT ---
log_section "8/15 Removing Bloat"
log_info "Keeping critical dependencies installed (will disable them later)..."

# Removed: policykit-1-gnome, plymouth*, mx-welcome, mx-tour (Preserved)
apt purge xdg-desktop-portal xdg-desktop-portal-gtk modemmanager \
          orca magnus onboard speech-dispatcher xfburn hplip \
          sane-utils blueman bluez flatpak baobab catfish \
          libsane1 \
          exim4-base exim4-config gnome-keyring gnome-keyring-pkcs11 libpam-gnome-keyring

dpkg --purge $(dpkg -l | grep "^rc" | awk '{print $2}') 2>/dev/null || true

# --- 10. UNLOCK SERVICES ---
log_section "9/15 Unlocking Services"
rm -f /usr/sbin/policy-rc.d
log_info "Service restarts unblocked."

# --- 11. KERNEL & HDD TWEAKS ---
log_section "10/15 System Tuning"
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

# --- 12. ZRAM & EARLYOOM ---
log_section "11/15 Memory Config"
if [ -f /etc/default/zramswap ]; then
    sed -i 's/^PERCENT=.*/PERCENT=60/' /etc/default/zramswap
fi
if [ -f /etc/default/earlyoom ]; then
    sed -i 's/^EARLYOOM_ARGS=.*/EARLYOOM_ARGS="-m 5 -s 5 --avoid ^(Xorg|nodm|fluxbox)$"/' /etc/default/earlyoom
fi

# --- 13. ACCESSIBILITY & TTY ---
log_section "12/15 Disabling Accessibility"
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

# --- 14. FIREFOX ---
log_section "13/15 Firefox Optimization"
FF_DIR="$USER_HOME/.mozilla/firefox"
if [ -d "$FF_DIR" ]; then
    find "$FF_DIR" -maxdepth 1 -type d -name "*.default*" | while read -r PROFILE_DIR; do
        log_info "Optimizing: $(basename "$PROFILE_DIR")"
        USER_JS="$PROFILE_DIR/user.js"
        [ -f "$USER_JS" ] && cp "$USER_JS" "${USER_JS}.bak"

        cat <<EOF > "$USER_JS"
// === v8.3 OPTIMIZATIONS ===
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

# --- 15. STARTUP SCRIPT (FIXED) ---
log_section "14/15 Startup Script"
STARTUP_FILE="$USER_HOME/.fluxbox/startup"
if [ -f "$STARTUP_FILE" ]; then
    cp "$STARTUP_FILE" "${STARTUP_FILE}.bak.$(date +%s)"
    
    # Disable dependencies we kept installed
    sed -i 's/^conkystart/#conkystart/g' "$STARTUP_FILE"
    sed -i 's|^/usr/lib/policykit-1-gnome/.*|#&|g' "$STARTUP_FILE"
    sed -i 's/^mx-welcome/#mx-welcome/g' "$STARTUP_FILE"
    sed -i 's/^picom/#picom/g' "$STARTUP_FILE"
    sed -i 's/^compton/#compton/g' "$STARTUP_FILE"

    read -r -d '' OPT_BLOCK << EOM || true
# === GOLD MASTER v8.3 ===
export NO_AT_BRIDGE=1
setxkbmap $KEYBOARD_LAYOUT &
lxpolkit &
# ========================
EOM
    if ! grep -q "GOLD MASTER" "$STARTUP_FILE"; then
        # FIX: Escape newlines for sed before insertion
        ESCAPED_BLOCK=$(echo "$OPT_BLOCK" | sed ':a;N;$!ba;s/\n/\\n/g')
        sed -i "/exec fluxbox/i $ESCAPED_BLOCK" "$STARTUP_FILE"
        log_info "Startup script updated."
    else
        log_info "Startup optimization already present."
    fi
    chown "${TARGET_USER}:${TARGET_USER}" "$STARTUP_FILE"
fi

# --- 16. CLEANUP & BOOT ---
log_section "15/15 Final Cleanup"
GRUB_FILE="/etc/default/grub"
sed -i "s/^GRUB_TIMEOUT=[0-9]*/GRUB_TIMEOUT=$GRUB_TIMEOUT_VAL/" "$GRUB_FILE"
sed -i 's/splash//g' "$GRUB_FILE"
if ! grep -q "fastboot" "$GRUB_FILE"; then
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="fastboot quiet /' "$GRUB_FILE"
fi
update-grub

rm -rf "$USER_HOME/.config/conky"
rm -f "$USER_HOME/.config/autostart/conky.desktop"

# Disable autostart for things we kept installed but don't want
[ -f /etc/xdg/autostart/mx-welcome.desktop ] && mv /etc/xdg/autostart/mx-welcome.desktop /etc/xdg/autostart/mx-welcome.desktop.bak
[ -f /etc/xdg/autostart/mx-tour.desktop ] && mv /etc/xdg/autostart/mx-tour.desktop /etc/xdg/autostart/mx-tour.desktop.bak

log_warn "ACTION REQUIRED: Confirm Auto-Remove."
apt autoremove --purge
apt clean

log_section "OPTIMIZATION COMPLETE (v8.3)"
log_info "Log file: $LOG_FILE"
log_info "Please reboot manually to apply changes."
