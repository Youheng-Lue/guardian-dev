#!/bin/bash
# This script is used to put the project to development mode
FILE=DEV_MODE
if test -f "$FILE"; then
    echo "In dev mode already. Exiting."
    exit 0
fi

echo 'Put folder into dev mode'
# Change imports to use relative imports
sed -i "s/from \./from _/g"  *.py
# Change file names to start with _
for i in *.py; do mv $i _$i; done
# Create a file to tell you that you are in dev mode
echo 'THIS HELPER FILE TELLS YOU THAT YOU ARE IN DEVELOPMENT MODE' > DEV_MODE
