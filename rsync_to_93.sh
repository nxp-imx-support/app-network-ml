rsync -rlptDvz --progress --exclude-from=./exclude.list -e "ssh" --rsync-path=/usr/local/bin/rsync ../lucid-ddos root@10.193.102.233:/home/root/NetworkingML
