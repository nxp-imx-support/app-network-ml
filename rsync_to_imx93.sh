#
# Copyright 2024 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

rsync -rlptDvz --progress --exclude-from=./exclude.list -e "ssh" --rsync-path=/usr/local/bin/rsync ../ETA_sys/ root@10.193.102.186:/home/root/NetworkingML