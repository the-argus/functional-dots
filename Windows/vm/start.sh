#!/bin/bash

source env.sh

qemu-system-x86_64 -enable-kvm \
	-cpu host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time \
	-smp $SMP\
	-m $MEMORY \
	-drive file=$DISKFILE,format=raw,cache=none
#	-device VGA,edid=on,xres=1920,yres=1080 \
