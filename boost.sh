#!/bin/bash
set -e
set -o pipefail

LOG_FILE="/var/log/mx_optimization_v8.6_$(date +%Y%m%d_%H%M%S).log"
touch "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

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
    [ -f /usr/sbin/policy-rc.d ] && rm -f /usr/sbin/policy-rc.d
    log_error "Script failed at line $1. Check $LOG_FILE."
    exit 1
}
trap 'error_handler $LINENO' ERR

KEYBOARD_LAYOUT="it"
LOCALES_TO_KEEP="en, en_US, en_US.UTF-8, it, it_IT, it_IT.UTF-8"
GRUB_TIMEOUT_VAL=0

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

echo ""
log_warn "SAFE MODE ACTIVE: Services locked to prevent logout."
echo "Press ENTER to start..."
read -r

log_section "1/15 Locking Services"
echo "#!/bin/sh" > /usr/sbin/policy-rc.d
echo "exit 101" >> /usr/sbin/policy-rc.d
chmod +x /usr/sbin/policy-rc.d
log_info "Service restarts blocked."

log_section "2/15 Pre-Fixing DPKG"
echo '#!/bin/sh' | tee /var/lib/dpkg/info/printer-driver-cups-pdf.prerm >/dev/null
echo '#!/bin/sh' | tee /var/lib/dpkg/info/printer-driver-cups-pdf.postrm >/dev/null
chmod +x /var/lib/dpkg/info/printer-driver-cups-pdf.prerm
chmod +x /var/lib/dpkg/info/printer-driver-cups-pdf.postrm
dpkg --remove --force-remove-reinstreq printer-driver-cups-pdf 2>/dev/null || true
log_info "Broken package locks cleared."

log_section "3/15 Installation"
apt update

log_warn "INTERACTIVE: Please confirm installation (Press Y when asked)."
apt install --no-install-recommends \
    debconf-utils nodm lxpolkit ufw p7zip-full unrar-free zip unzip \
    ffmpeg libavcodec-extra intel-microcode amd64-microcode \
    localepurge earlyoom

log_section "4/15 Configuring Tools"

echo "localepurge localepurge/nopurge multiselect $LOCALES_TO_KEEP" | debconf-set-selections
echo "localepurge localepurge/use-dpkg-feature boolean true" | debconf-set-selections
echo "localepurge localepurge/summary boolean true" | debconf-set-selections
echo "localepurge localepurge/verbose boolean false" | debconf-set-selections

apt-mark manual mx-apps-fluxbox mx-fluxbox mx-updater cleanup-notifier-mx

NODM_FILE="/etc/default/nodm"
if [ -f "$NODM_FILE" ]; then
    sed -i 's/^NODM_ENABLED=.*/NODM_ENABLED=true/' "$NODM_FILE"
    sed -i "s/^NODM_USER=.*/NODM_USER=$TARGET_USER/" "$NODM_FILE"
fi

if [ -x "/etc/init.d/lightdm" ]; then update-rc.d lightdm disable || true; fi
if [ -x "/etc/init.d/nodm" ]; then update-rc.d nodm enable || true; fi

log_section "5/15 Disabling Services"
SERVICES=(
    cups cups-browsed bluetooth speech-dispatcher plymouth 
    cryptdisks cryptdisks-early rsyslog uuidd smbd nmbd 
    avahi-daemon rpcbind nfs-common chrony exim4 saned
)
for service in "${SERVICES[@]}"; do
    if [ -x "/etc/init.d/$service" ]; then
        update-rc.d "$service" disable 2>/dev/null || true
    fi
done

log_section "6/15 Removing Bloat"
log_warn "INTERACTIVE: Please confirm removal (Press Y when asked)."

apt purge \
    preload \
    printer-driver-* cups* system-config-printer* \
    network-manager-openvpn network-manager-pptp network-manager-vpnc \
    openconnect openvpn ppp wvdial mobile-broadband-provider-info \
    telnet ftp whois sendemail \
    open-vm-tools fprintd \
    mc galculator sysbench samba smbclient python3-smbc \
    xorriso dvd+rw-tools libburn4t64 genisoimage growisofs \
    cdparanoia vcdimager djvulibre-bin mtools pacpl \
    guvcview bluez-obexd testdisk nwipe gtkhash \
    conky-all mx-conky xfce4-clipman clipman \
    xdg-desktop-portal xdg-desktop-portal-gtk modemmanager \
    orca magnus onboard speech-dispatcher xfburn hplip \
    sane-utils blueman bluez flatpak baobab catfish \
    libsane1 mugshot \
    mx-tour mx-welcome mx-welcome-data \
    exim4-base exim4-config gnome-keyring gnome-keyring-pkcs11 libpam-gnome-keyring

log_info "Cleaning residual configs..."
dpkg --purge $(dpkg -l | grep "^rc" | awk '{print $2}') 2>/dev/null || true

log_section "7/15 Unlocking Services"
rm -f /usr/sbin/policy-rc.d

log_section "8/15 System Tuning"
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

sed -i 's/errors=remount-ro/noatime,nodiratime,commit=60,errors=remount-ro/' /etc/fstab
if ! grep -q "tmpfs /tmp" /etc/fstab; then
    echo "tmpfs /tmp tmpfs defaults,noatime,mode=1777,size=256M 0 0" >> /etc/fstab
fi
if ! grep -q "tmpfs /var/log" /etc/fstab; then
    echo "tmpfs /var/log tmpfs defaults,noatime,mode=0755,size=128M 0 0" >> /etc/fstab
fi

log_section "9/15 Memory Services"
if [ -f /etc/default/zramswap ]; then sed -i 's/^PERCENT=.*/PERCENT=60/' /etc/default/zramswap; fi
if [ -f /etc/default/earlyoom ]; then sed -i 's/^EARLYOOM_ARGS=.*/EARLYOOM_ARGS="-m 5 -s 5 --avoid ^(Xorg|nodm|fluxbox)$"/' /etc/default/earlyoom; fi

service zramswap start || true
update-rc.d zramswap enable || true
update-rc.d zramswap defaults || true

service earlyoom start || true
update-rc.d earlyoom enable || true

log_section "10/15 Cleanup"
TARGETS=("/usr/libexec/at-spi-bus-launcher" "/usr/libexec/at-spi2-registryd" "/etc/xdg/autostart/at-spi-dbus-bus.desktop")
for target in "${TARGETS[@]}"; do
    if [ -f "$target" ]; then dpkg-divert --add --rename --divert "$target.disabled" "$target"; fi
done

sed -i 's/^[3-6]:23:respawn:/#&/' /etc/inittab
CURRENT_HOSTNAME=$(hostname)
if ! grep -q "127.0.1.1.*$CURRENT_HOSTNAME" /etc/hosts; then echo "127.0.1.1 $CURRENT_HOSTNAME" >> /etc/hosts; fi

log_section "11/15 Firefox Optimization"
FF_DIR="$USER_HOME/.mozilla/firefox"
if [ -d "$FF_DIR" ]; then
    find "$FF_DIR" -maxdepth 1 -type d -name "*.default*" | while read -r PROFILE_DIR; do
        USER_JS="$PROFILE_DIR/user.js"
        cat <<EOF > "$USER_JS"
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

log_section "12/15 Startup Script"
STARTUP_FILE="$USER_HOME/.fluxbox/startup"
if [ -f "$STARTUP_FILE" ]; then
    cp "$STARTUP_FILE" "${STARTUP_FILE}.bak.$(date +%s)"
    
    for item in conkystart mx-welcome picom compton clipman; do
        sed -i "s/^$item/#$item/g" "$STARTUP_FILE"
    done
    sed -i 's|^/usr/lib/policykit-1-gnome/.*|#&|g' "$STARTUP_FILE"

    read -r -d '' OPT_BLOCK << EOM || true
export NO_AT_BRIDGE=1
setxkbmap $KEYBOARD_LAYOUT &
lxpolkit &
EOM
    if ! grep -q "lxpolkit" "$STARTUP_FILE"; then
        ESCAPED_BLOCK=$(echo "$OPT_BLOCK" | sed ':a;N;$!ba;s/\n/\\n/g')
        sed -i "/exec fluxbox/i $ESCAPED_BLOCK" "$STARTUP_FILE"
    fi
    chown "${TARGET_USER}:${TARGET_USER}" "$STARTUP_FILE"
fi

log_section "13/15 Grub Config"
GRUB_FILE="/etc/default/grub"
sed -i "s/^GRUB_TIMEOUT=[0-9]*/GRUB_TIMEOUT=$GRUB_TIMEOUT_VAL/" "$GRUB_FILE"
sed -i 's/splash//g' "$GRUB_FILE"
if ! grep -q "fastboot" "$GRUB_FILE"; then
    sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="/GRUB_CMDLINE_LINUX_DEFAULT="fastboot quiet /' "$GRUB_FILE"
fi
update-grub

log_section "14/15 Final Cleanup"
rm -rf "$USER_HOME/.config/conky"
rm -f "$USER_HOME/.config/autostart/"{conky,mx-welcome,mx-tour,clipman}.desktop
rm -f /etc/init.d/*.dpkg-distrib

log_info "Running Localepurge..."
dpkg-reconfigure -f noninteractive localepurge
localepurge

log_warn "INTERACTIVE: Confirm Auto-Remove."
apt autoremove --purge
apt clean

log_section "OPTIMIZATION COMPLETE"
log_info "Log file: $LOG_FILE"
log_info "Please reboot manually."
