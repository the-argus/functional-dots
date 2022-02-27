#!/bin/bash

source env.sh

qemu-system-x86_64 -boot order=d \
	-drive file=$DISKFILE,index=0,media=disk,if=virtio,format=raw \
	-drive file=$ISO_PATH,index=2,media=cdrom \
	-drive file=$VIRTIO_PATH,index=3,media=cdrom \
	-m $MEMORY -enable-kvm \
	-cpu host \
	-vga virtio
