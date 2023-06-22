#!/bin/bash
echo $FLAG > /flag
chown root:ctf /home/ctf/pwn
/etc/init.d/xinetd start
tail -f /dev/null
