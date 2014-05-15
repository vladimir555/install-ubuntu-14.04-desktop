add-apt-repository "deb http://packages.mate-desktop.org/repo/ubuntu raring main"
apt-get update
apt-get -y install mate-archive-keyring
apt-get update
apt-get -y install \
 xinit qt4-qtconfig \
 mate-core \
 mate-media-pulse \
 mate-system-monitor mate-window-manager mate-themes mate-applets mate-calc \
 mate-sensors-applet mate-text-editor mate-doc-utils mate-screensaver \
 mate-power-manager eom evince lightdm lightdm-gtk-greeter \
 dconf-tools
