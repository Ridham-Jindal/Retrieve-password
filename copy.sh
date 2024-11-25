#!/bin/bash

DEST_FILE="copy.txt"

sudo cp /etc/shadow "$DEST_FILE"
echo "/etc/shadow copied to $DEST_FILE."

echo "Scanning the contents of $DEST_FILE:"
sudo cat "$DEST_FILE"
