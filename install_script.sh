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
echo "Would you like to add $(whoami) to the group? y/n"
read user_response

if [ $user_response == y ]; then
	echo "Adding $(whoami) to the group"
	sudo usermod -aG firewhal-admin $current_user
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

echo "Creating /opt/firewhal directory in case it doesn't exist"
# Create the destination directory if it doesn't exist
sudo mkdir -p /opt/firewhal

echo "Installing primary workspace binaries to /opt/firewhal"

sudo cp target/debug/firewhal-ipc /opt/firewhal
sudo cp target/debug/firewhal-discord-bot /opt/firewhal

echo "Changing directory to aya workspace"
cd ../aya-workspace

echo "Building aya binaries"
echo $(cargo build)

echo "Installing aya workspace binaries to /opt/firewhal"

echo "Ensuring proper permissions for access purposes"
sudo chmod 755 /opt/firewhal/*

echo "Installation complete! Please log out and log back in to update group status"


