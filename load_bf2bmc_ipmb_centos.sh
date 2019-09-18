#!/bin/sh

# Copyright (c) 2017, Mellanox Technologies
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and documentation are those
# of the authors and should not be interpreted as representing official policies,
# either expressed or implied, of the FreeBSD Project.


# This script stops the mlx_ipmid service and unloads the ipmb_dev_int
# driver. Then, it loads the ipmb_host driver on top of ipmi_msghandler
# and ipmi_devintf. This allows the BF to send IPMB requests to the BMC
# via SMBus 2.
#
# Here, the ipmb_host driver is registered at I2C address 0x30
# and communicates with the BMC registered at address 0x10.
# If you wish to change:
#     1) the BMC address, you may modify the SLAVE_ADD variable.
#     2) the BF address, you may modify the IPMB_HOST_ADD variable.
#
# On the BlueWhale system, make sure to run this script after running
# the BMC's version of the load_bf2bmc_ipmb.sh script.

set -e

I2C2_NEW_DEV=/sys/bus/i2c/devices/i2c-2/new_device
I2C2_DEL_DEV=/sys/bus/i2c/devices/i2c-2/delete_device

SLAVE_ADD=0x10

IPMB_HOST_ADD=0x1030
IPMB_DEV_INT_ADD=0x1011

systemctl stop mlx_ipmid

echo $IPMB_DEV_INT_ADD > $I2C2_DEL_DEV
rmmod ipmb_dev_int

if [[ $(ls /lib/modules/$(uname -r)/kernel/drivers/char/ipmi | grep ipmi_msghandler.ko) == "ipmi_msghandler.ko" ]]; then
	modprobe ipmi_msghandler
else
	echo "/lib/modules/$(uname -r)/kernel/drivers/char/ipmi/ipmi_msghandler.ko file does not exist."
	echo "So it should be built and loaded manually before running this script."
fi

if [[ $(ls /lib/modules/$(uname -r)/kernel/drivers/char/ipmi | grep ipmi_devintf.ko) == "ipmi_devintf.ko" ]]; then
	modprobe ipmi_devintf
else
	echo "/lib/modules/$(uname -r)/kernel/drivers/char/ipmi/ipmi_devintf.ko file does not exist."
	echo "So it should be built and loaded manually before running this script."
fi

if [ $(ls /tmp/ipmb-host/ipmb-host.ko) ]; then
	insmod /tmp/ipmb-host/ipmb-host.ko slave_add=$SLAVE_ADD
else
	echo "/tmp/ipmb-host/ipmb-host.ko file does not exist"
	echo "Please build it before running this script"
fi

echo ipmb-host $IPMB_HOST_ADD > $I2C2_NEW_DEV
