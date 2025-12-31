#!/bin/bash

# =================================================================
# MX Linux Fluxbox ULTIMATE Optimization Script (v2.0 - 2025)
# Features: 
# - RAM Target: < 200MB Idle
# - Auto-CPU Detection (Microcode)
# - zRAM Optimized (Compression > Paging)
# - EarlyOOM (Prevents hard freezes)
# - Firefox Hardened + RAM Cache (No Disk I/O)
# - OnlyOffice (Official Repo)
# =================================================================

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root (sudo)."
  exit
fi

echo "--- Starting Ultimate Optimization (v2.0) ---"

# 0. CPU Detection & Variable Setup
echo "[0/11] Detecting Hardware..."
CPU_VENDOR=$(grep -m 1 'vendor_id' /proc/cpuinfo | awk '{print $3}')
if [ "$CPU_VENDOR" == "GenuineIntel" ]; then
    echo " -> Intel CPU detected."
    MICROCODE="intel-microcode"
elif [ "$CPU_VENDOR" == "AuthenticAMD" ]; then
    echo " -> AMD CPU detected."
    MICROCODE="amd64-microcode"
else
    MICROCODE=""
fi

# 1. Package Installation (Essentials & Dependencies)
echo "[1/11] Installing essential utilities..."
apt update

# Install core tools, correct microcode, and EarlyOOM (Critical for low RAM)
apt install -y nodm ufw p7zip-full unrar-free zip unzip ffmpeg \
               libavcodec-extra $MICROCODE earlyoom \
               localepurge lxpolkit network-manager-gnome nitrogen \
               volumeicon-alsa fonts-croscore gnupg ca-certificates curl

# Configure Localepurge (Automated - Keep only English and Italian)
# Prevents the interactive popup during install
echo "localepurge localepurge/nopurge multiselect en_US.UTF-8, it_IT.UTF-8" | debconf-set-selections
localepurge

# 2. OnlyOffice Installation (Official Repository)
echo "[2/11] Adding OnlyOffice Repository and Installing..."
mkdir -p /usr/share/keyrings
curl -fsSL https://download.onlyoffice.com/repo/onlyoffice.key | gpg --dearmor -o /usr/share/keyrings/onlyoffice.gpg
echo "deb [signed-by=/usr/share/keyrings/onlyoffice.gpg] https://download.onlyoffice.com/repo/debian squeeze main" > /etc/apt/sources.list.d/onlyoffice.list
apt update
apt install -y onlyoffice-desktopeditors

# 3. Service Management (Disabling Bloat)
echo "[3/11] Disabling unnecessary background services..."
SERVICES=(
    cups cups-browsed bluetooth speech-dispatcher 
    plymouth cryptdisks cryptdisks-early 
    rsyslog uuidd smbd nmbd avahi-daemon 
    rpcbind nfs-common chrony exim4 saned
)

for service in "${SERVICES[@]}"; do
    service "$service" stop 2>/dev/null
    update-rc.d "$service" disable 2>/dev/null
done

# 4. Aggressive Purging
echo "[4/11] Purging heavy packages and keyring..."
apt purge -y xdg-desktop-portal xdg-desktop-portal-gtk modemmanager \
           orca magnus onboard speech-dispatcher xfburn hplip \
           sane-utils blueman bluez flatpak mx-updater \
           cleanup-notifier-mx mx-welcome mx-tour baobab catfish \
           conky-all policykit-1-gnome libsane1 \
           exim4-base exim4-config lightdm \
           gnome-keyring gnome-keyring-pkcs11 libpam-gnome-keyring

# Clean up "rc" packages
dpkg --purge $(dpkg -l | grep "^rc" | awk '{print $2}') 2>/dev/null

# 5. NODM Configuration (Auto-Login)
echo "[5/11] Configuring NODM for Auto-login..."
sed -i "s/^NODM_USER=.*/NODM_USER=${SUDO_USER}/" /etc/default/nodm
sed -i "s/^NODM_ENABLED=.*/NODM_ENABLED=true/" /etc/default/nodm

# 6. Kernel, EarlyOOM & System Tweaks
echo "[6/11] Applying kernel tweaks & Anti-Freeze..."

# Swappiness 100 + zRAM = Aggressively compress idle apps to keep system responsive
cat <<EOF > /etc/sysctl.d/99-minimal.conf
vm.swappiness=100
vm.vfs_cache_pressure=50
kernel.nmi_watchdog=0
net.ipv6.conf.all.disable_ipv6 = 1
EOF
sysctl --system

# Configure EarlyOOM: Kill browser if RAM < 5% to prevent total system freeze
# Avoid killing the display manager or window manager
sed -i 's/^EARLYOOM_ARGS=.*/EARLYOOM_ARGS="-m 5 -s 5 --avoid ^(Xorg|nodm|fluxbox)$"/' /etc/default/earlyoom
service earlyoom restart

# FS Optimization
sed -i 's/errors=remount-ro/noatime,errors=remount-ro/' /etc/fstab

# 7. zRAM Configuration (60% of RAM)
echo "[7/11] Configuring zRAM..."
if [ -f /etc/default/zramswap ]; then
    sed -i 's/^PERCENT=.*/PERCENT=60/' /etc/default/zramswap
    update-rc.d zramswap defaults
    service zramswap restart
fi

# 8. UI & Accessibility Hard-Kill (Persistent)
echo "[8/11] Permanently disabling accessibility bus..."
# Using dpkg-divert ensures updates don't reinstall these files
TARGETS=(
    "/usr/libexec/at-spi-bus-launcher"
    "/usr/libexec/at-spi2-registryd"
    "/etc/xdg/autostart/at-spi-dbus-bus.desktop"
)

for target in "${TARGETS[@]}"; do
    if [ -f "$target" ]; then
        dpkg-divert --add --rename --divert "$target.disabled" "$target"
    fi
done

# Reduce TTYs to 2
sed -i 's/^[3-6]:23:respawn:/#&/' /etc/inittab

# 9. Firefox Optimization (uBlock + RAM Cache)
echo "[9/11] Hardening Firefox (Policies + User.js)..."

mkdir -p /etc/firefox/policies
cat <<EOF > /etc/firefox/policies/policies.json
{
  "policies": {
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisablePocket": true,
    "DisableSystemAddonUpdate": true,
    "DontCheckDefaultBrowser": true,
    "DisplayBookmarksToolbar": "never",
    "Extensions": {
      "Install": [
        "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi"
      ]
    },
    "UserMessaging": {
      "ExtensionRecommendations": false,
      "FeatureRecommendations": false,
      "UrlbarInterventions": false,
      "SkipOnboarding": true,
      "Locked": true
    }
  }
}
EOF

USER_HOME=$(eval echo "~${SUDO_USER}")
FF_DIR="$USER_HOME/.mozilla/firefox"

if [ -d "$FF_DIR" ]; then
    find "$FF_DIR" -maxdepth 1 -type d -name "*.default*" | while read profile; do
        echo "Injecting user.js into: $profile"
        cat <<EOF > "$profile/user.js"
// PERFORMANCE
user_pref("accessibility.force_disabled", 1);
user_pref("dom.ipc.processCount", 2);
user_pref("network.prefetch-next", false);

// CACHE (RAM ONLY - Reduces Stutter)
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.memory.enable", true);
user_pref("browser.cache.memory.capacity", 256000); 
user_pref("browser.sessionstore.interval", 15000000);

// PRIVACY
user_pref("toolkit.telemetry.enabled", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("extensions.pocket.enabled", false);
user_pref("browser.shell.checkDefaultBrowser", false);
EOF
        chown "${SUDO_USER}:${SUDO_USER}" "$profile/user.js"
    done
fi

# 10. Fluxbox Startup Script
echo "[10/11] Recreating Fluxbox startup script..."
STARTUP_FILE="$USER_HOME/.fluxbox/startup"
cp "$STARTUP_FILE" "${STARTUP_FILE}.bak_$(date +%F)"

cat <<EOF > "$STARTUP_FILE"
#!/bin/sh
# -------------------------------------------------
# Optimized Fluxbox Startup (Italy / Minimal RAM)
# -------------------------------------------------

localize_fluxbox_menu-mx
export NO_AT_BRIDGE=1
setxkbmap it &

# LXPolkit (Required for Root Apps)
/usr/lib/x86_64-linux-gnu/lxpolkit &

# Network Manager (No Agent = No Keyring Errors)
nm-applet --no-agent &

# Audio
pipewire-start &
sleep 1
volumeicon -c volumeicon-fluxbox &

# Wallpaper (Nitrogen)
if [ -x "/usr/bin/nitrogen" ]; then
    if [ -e "\$HOME/.config/nitrogen/bg-saved.cfg" ]; then
        nitrogen --restore &
    else
        xsetroot -solid "#222222"
    fi
fi

# Tint2 Panel
tint2session &

# Power Saving
xset s on
xset s 600 600
xset -dpms

# Start Fluxbox
exec dbus-launch --exit-with-session fluxbox
EOF

chown ${SUDO_USER}:${SUDO_USER} "$STARTUP_FILE"
chmod +x "$STARTUP_FILE"

# 11. Enable Sudo-less Poweroff (For Fluxbox Menu)
echo "[11/11] Enabling sudo-less Shutdown/Reboot..."
echo "${SUDO_USER} ALL=(ALL) NOPASSWD: /sbin/poweroff, /sbin/reboot" > /etc/sudoers.d/fluxbox-power
chmod 0440 /etc/sudoers.d/fluxbox-power

# Patch Menu (Attempt)
MENU_FILE="$USER_HOME/.fluxbox/menu"
if [ -f "$MENU_FILE" ]; then
    sed -i 's/\[exit\] (Exit)/\[exec\] (Shutdown) {sudo poweroff}\n\t\[exec\] (Reboot) {sudo reboot}\n\t\[exit\] (Logout)/' "$MENU_FILE"
fi

# Final Cleanup
apt autoremove --purge -y
apt clean

echo "===================================================="
echo " OPTIMIZATION v2.0 COMPLETE"
echo "===================================================="
echo " 1. SYSTEM: Swappiness set to 100 for zRAM efficiency."
echo " 2. SAFETY: EarlyOOM installed (prevents freezing)."
echo " 3. NETWORK: Connect via icon. If password fails,"
echo "    mark connection 'Available to all users'."
echo "===================================================="
echo " Please reboot now."
