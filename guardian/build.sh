#!/bin/bash
# This script is used to put the project to production mode
FILE=DEV_MODE
if [ ! -f "$FILE" ]; then
    echo "In production mode already. Exiting."
    exit 0
fi
echo 'Putting the folder to production mode'
rm $FILE
# Change imports back to normal
sed -i "s/from \_/from \./g"  *.py
# Change file names back to normal
python3 -c '
from glob import glob
import os
for fname in glob("*.py"):
    if fname.startswith("_"):
        os.rename(fname, fname[1:])
'