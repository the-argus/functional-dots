#!/bin/bash

source config


# qemu-system-x86_64 -runas $VM_USER -enable-kvm \
  # -nographic -vga none -parallel none -serial none \
  # -enable-kvm \
  # -m $RAM \
  # -cpu host,kvm=off,hv_relaxed,hv_spinlocks=0x1fff,hv_time,hv_vapic,hv_vendor_id=0xDEADBEEFFF \
  # -rtc clock=host,base=localtime \
  # -smp $CORES,sockets=1,cores=$(( $CORES / 2 )),threads=2 \
  # -device vfio-pci,host=$IOMMU_GPU,multifunction=on,x-vga=on,romfile=$VBIOS \
  # -device vfio-pci,host=$IOMMU_GPU_AUDIO \
  # -device virtio-net-pci,netdev=n1 \
  # -netdev user,id=n1 \
  # -drive if=pflash,format=raw,readonly,file=$OVMF \
  # -drive media=cdrom,file=$WINDOWS_ISO,id=cd1,if=none \
  # -device ide-cd,bus=ide.1,drive=cd1 \
  # -drive media=cdrom,file=$VIRTIO,id=cd2,if=none \
  # -device ide-cd,bus=ide.1,drive=cd2 \
  # -device virtio-scsi-pci,id=scsi0 \
  # -device scsi-hd,bus=scsi0.0,drive=rootfs \
  # -drive id=rootfs,file=$WINDOWS_IMG,media=disk,format=qcow2,if=none >> $LOG 2>&1 &


qemu-system-x86_64 -runas $VM_USER \
    -enable-kvm \
    -nographic -vga none -parallel none -serial none \
    -m $RAM \
    -cpu host,kvm=on,hv_relaxed,hv_spinlocks=0x1fff,hv_time,hv_vapic,hv_vendor_id=0xDEADBEEFFF \
    -rtc clock=host,base=localtime \
    -smp $CORES,sockets=1,cores=$(( $CORES / 2 )),threads=2 \
    -device vfio-pci,host=$IOMMU_GPU,multifunction=on,x-vga=on,romfile="" \
    -device virtio-net-pci,netdev=n1 \
    -netdev user,id=n1 \
    -drive file=$WINDOWS_IMG,media=disk,format=raw >> $LOG 2>&1

