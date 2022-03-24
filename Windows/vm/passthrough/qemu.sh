#!/bin/bash

source config

qemu-system-x86_64 -runas $VM_USER \
    -enable-kvm \
    -m $RAM \
    -cpu host,kvm=on,hv_relaxed,hv_spinlocks=0x1fff,hv_time,hv_vapic,hv_vendor_id=0xDEADBEEFFF \
    -rtc clock=host,base=localtime \
    -smp $CORES,sockets=1,cores=$(( $CORES / 2 )),threads=2 \
    -device virtio-net-pci,netdev=n1 \
    -netdev user,id=n1 \
    -drive file=$WINDOWS_IMG,media=disk,format=raw >> $LOG 2>&1
    #-device vfio-pci,host=$IOMMU_GPU,multifunction=on,x-vga=on \

