#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

echo "Checking for firewhal-admin group"

if getent group | grep -q "firewhal-admin"; then
	echo "The firewhal-admin group exists. Continuing"
else
	echo "The firewhal-admin group does not exist. Creating group"
	sudo groupadd --system firewhal-admin

fi

current_user=$(whoami)


echo "Checking if current user is already part of firewhal-admin group"
if [ id -nG $current_user | grep -qw firewhal-admin ]; then
	echo "$current_user is not part of the group"


	echo "Would you like to add the current user $current_user to the group? y/n"
	read user_response

	if [ $user_response == y ]; then
		echo "Adding $current_user to the group"
		sudo usermod -aG firewhal-admin $current_user
	fi
fi

echo "Killing previous instances of FireWhal"
sudo pkill -f firewhal-daemon
sudo pkill -f firewhal-kernel
sudo pkill -f firewhal-ipc
sudo pkill -f firewhal-discord-bot

echo "Changing directory to primary workspace"
cd primary-workspace

echo "Building primary binaries"
# Build all binaries in the workspace in release mode
echo $(cargo build)

echo "Creating /opt/firewhal/bin directory in case it doesn't exist"
# Create the destination directory if it doesn't exist
sudo mkdir -p /opt/firewhal/bin

echo "Installing primary workspace binaries to /opt/firewhal/bin"

sudo cp target/debug/firewhal-ipc /opt/firewhal/bin
sudo cp target/debug/firewhal-discord-bot /opt/firewhal/bin

echo "Installing daemon to /usr/local/sbin (the daemon will be started from a systemd unit file and located in /opt/firewhal/bin in the future)"
sudo cp target/debug/firewhal-daemon /usr/local/sbin

echo "Installing Discord token and user ID"
sudo cp firewhal-discord-bot/.env /opt/firewhal/bin

echo "Installing TUI to /usr/local/bin"
sudo cp target/debug/firewhal-tui /usr/local/bin

echo "Changing directory to aya workspace"
cd ../aya-workspace

echo "Building aya binaries"
echo $(cargo build)

echo "Installing aya workspace binaries to /opt/firewhal/bin"
sudo cp target/debug/firewhal-kernel /opt/firewhal/bin

echo "Ensuring proper permissions for access purposes"
sudo chmod 755 /opt/firewhal/bin/*

echo "Installation complete! Please log out and log back in to update group status"


