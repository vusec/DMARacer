#!/usr/bin/env bash

APPEND="${KERNEL_PARAMS:+$KERNEL_PARAMS }nokaslr nosmp maxcpus=1 rcu_nocbs=0 nmi_watchdog=0 ignore_loglevel modules=sd-mod,usb-storage,ext4 rootfstype=ext4 earlyprintk=serial"
MEMORY="32768"

TYPE=$1
if [[ $TYPE = "syzkaller" ]]; then
  RAMDISK=
  HDA="${SYZKALLER_IMG}/bullseye.img"
  if [ -n "${SYZKALLER_SSH_PORT}" ]; then
    NICMODEL="${NICMODEL:-e1000}"
    INPUT_DEV="${INPUT_DEV:usb-kbd}"
    NET1="nic,model=${NICMODEL}"
    NET2="user,host=10.0.2.10,hostfwd=tcp::${SYZKALLER_SSH_PORT}-:22"
    # Setup iperf port.
    NET2="${NET2}" #,hostfwd=tcp::5001-:5001"
  fi
else
  RAMDISK="${INITRAMFS}"
  HDA=
fi

if [[ $ARCH = "x86" ]]; then
  APPEND+=" root=/dev/sda"
  KERNEL="-kernel ${KERNEL}/arch/x86/boot/bzImage"
  APPEND+=" biosdevname=0 kvm-intel.emulate_invalid_guest_state=1 kvm-intel.enable_apicv=1 kvm-intel.enable_shadow_vmcs=1 kvm-intel.ept=1 kvm-intel.eptad=1 kvm-intel.fasteoi=1 kvm-intel.flexpriority=1 kvm-intel.nested=1 kvm-intel.pml=1 kvm-intel.unrestricted_guest=1 kvm-intel.vmm_exclusive=1 kvm-intel.vpid=1 net.ifnames=0"
  QEMU="qemu-system-x86_64"
  CPU="qemu64"
  APPEND+=" console=ttyS0" # TODO: Not sure if this is necessary
elif [[ $ARCH = "arm64" ]]; then
  APPEND+=" root=/dev/vda"
  KERNEL="-kernel ${KERNEL}/arch/arm64/boot/Image"
  QEMU="qemu-system-aarch64"
  MACHINE="virt"
  CPU="cortex-a57"
fi

if [ -n "${QEMU_BUILD}" ]; then
  QEMU=${QEMU_BUILD}/${QEMU}
fi


STORAGE_ARGS=""
if [ -n "$STORAGE_ARGS" ]; then
  STORAGE_BACKEND=".device-storage.bin"
  rm -f ${STORAGE_BACKEND}
  dd if=/dev/zero of=${STORAGE_BACKEND}  bs=1M count=512
  STORAGE_ARGS="-drive id=drv0,if=none,format=raw,file=${STORAGE_BACKEND} -device ${STORAGE_DEV},drive=drv0"
fi

set -x
${QEMU} \
  ${KERNEL} \
  ${MACHINE:+ -machine ${MACHINE}} \
  ${APPEND:+ -append "${APPEND}"} \
  ${RAMDISK:+ -initrd "${RAMDISK}"} \
  ${HDA:+ -hda "${HDA}"} \
  ${ATTACH_GDB:+ -gdb tcp::${GDB_PORT}} \
  ${ATTACH_GDB:+ -S} \
  ${NET1:+ -net ${NET1}} \
  ${NET2:+ -net ${NET2}} \
  ${BENCHMARK_QEMU_ARGS} \
  -device sdhci-pci \
  -device qemu-xhci,id=xhci\
  -usb \
  ${STORAGE_ARGS} \
  ${INPUT_DEV:+ ${INPUT_DEV}} \
  ${ENABLE_KVM:+ -enable-kvm} \
  ${QEMUSOCKET:+ -monitor unix:${QEMUSOCKET},server,nowait} \
  -smp 1 \
  ${VMDRIVE:+ -drive if=none,format=qcow2,file="${VMDRIVE}"} \
  ${LOADVM:+ -loadvm "${LOADVM}"} \
  -cpu ${CPU} \
  -m ${MEMORY} \
  -echr 17 \
  -serial mon:stdio \
  -snapshot \
  -no-reboot \
  -display none \
  -vnc :0,to=100 \
  -L ${QEMU_SOURCE}/pc-bios
