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


# This script unloads the ipmb_host module along with its dependencies:
# ipmi_devintf and ipmi_msghandler. Then, it loads the ipmb_dev_int driver
# and starts the mlx_ipmid service.
# This allows the BF to receive IPMB requests from the BMC, process them,
# and send a response back via SMBus 2.
#
# Here, the ipmb_dev_int driver is registered at I2C address 0x11.
#
# On the BlueWhale system, make sure to run this script before running
# the BMC's version of the load_bmc2bf_ipmb.sh script.

set -e

I2C2_DEL_DEV=/sys/bus/i2c/devices/i2c-2/delete_device
IPMB_HOST_ADD=0x1030

rmmod ipmb_host
rmmod ipmi_devintf
rmmod ipmi_msghandler
echo $IPMB_HOST_ADD > $I2C2_DEL_DEV

modprobe ipmb_dev_int

systemctl start mlx_ipmid
