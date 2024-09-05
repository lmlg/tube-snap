#!/bin/bash
snap=$(grep "name:" snapcraft.yaml | awk '{print $2}')
echo "renaming ${snap}_*.snap to ${snap}.snap"
echo -n "pwd: "
pwd
ls -al
mv ${snap}_*.snap ${snap}.snap
