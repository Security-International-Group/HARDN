# SELinux configuration script
# we will disable apparmor and enable selinux
# then we will set the enforcing mode to permissive
# finally we will relabel the filesystem
# and reboot the system 
source /usr/share/hardn/functions.sh
HARDN_STATUS "Disabling AppArmor..."
systemctl stop apparmor
systemctl disable apparmor
apt-get remove -y apparmor apparmor-utils
HARDN_STATUS "AppArmor disabled."
HARDN_STATUS "Installing SELinux..."
apt-get install -y selinux-basics selinux-policy-default auditd
HARDN_STATUS "SELinux installed."
HARDN_STATUS "Enabling SELinux..."
selinux-activate
HARDN_STATUS "SELinux enabled."
HARDN_STATUS "Setting SELinux to permissive mode..."
setenforce 0
sed -i 's/SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config
HARDN_STATUS "SELinux set to permissive mode."
HARDN_STATUS "Relabeling filesystem..."
touch /.autorelabel
HARDN_STATUS "Filesystem relabeling scheduled."
HARDN_STATUS "Rebooting system to apply changes..."
reboot
# Note: The system will reboot immediately after this command.