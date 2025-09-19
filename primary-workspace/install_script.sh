#!/bin/bash
set -e # Exit immediately if a command exits with a non-zero status.

echo "Running build command"

# Build all binaries in the workspace in release mode
cargo build

echo "Installing binaries to /opt/firewhal/"

# Create the destination directory if it doesn't exist
sudo mkdir -p /opt/firewhal

# Copy the binaries
sudo cp target/debug/firewhal-ipc /opt/firewhal
sudo cp target/debug/firewhal-discord-bot /opt/firewhal

# Ensure they have the correct permissions
sudo chmod 755 /opt/firewhal/*

echo "Installation complete!"

