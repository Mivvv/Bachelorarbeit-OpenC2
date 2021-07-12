#!/bin/bash

# removes the last line in our sudoers file
user=$(whoami)
sudo sed '31,32d' -i /etc/sudoers

