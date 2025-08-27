#!/bin/bash

set -e
set -x

DEVICE_NAME=$(lsblk | grep -v sda | grep -v NAME | cut -d ' ' -f 1 | head -n1)
echo "Available devices"
lsblk
ls -alh /dev/${DEVICE_NAME}
echo "Target device ${DEVICE_NAME}"

echo "Reading stuff from device"
set +e
dd if=/dev/${DEVICE_NAME} of=/dev/null bs=1M count=2
set -e

echo "Devices after formatting"
lsblk

PARTITION=/dev/${DEVICE_NAME}2

set +e

prepare_fresh_disk () {
    echo "Clearing device"
    dd if=/dev/zero of=/dev/${DEVICE_NAME} bs=1M count=4
    sync
    lsblk
    echo "Unmounting before formatting..."
    umount /mnt
    mount
    sed -e 's/\s*\([\+0-9a-zA-Z]*\).*/\1/' << EOF | fdisk /dev/${DEVICE_NAME}
  o # clear the in memory partition table
  n # new partition
  p # primary partition
  1 # partition number 1
    # default - start at beginning of disk 
  +1M # 1 MB boot parttion
  n # new partition
  p # primary partition
  2 # partion number 2
    # default, start immediately after preceding partition
    # default, extend partition to end of disk
  a # make a partition bootable
  1 # bootable partition is partition 1 -- /dev/sda1
  p # print the in-memory partition table
  w # write the partition table
  q # and we're done
EOF
}

fuzz_mnt () {
  for try in {1..4}; do
    echo "Iteration $try"
    mount -t ${fs_kind} "${PARTITION}" /mnt
    cd /mnt
    # Create some directories
    mkdir -p some/list/of/$try/subdirectories
    # Write some data.
    dd if=/dev/urandom of=some_file_$try bs=1M count=1
    # Read and write some data
    cp some_file_$try some_file_$try.bak
    cd /
    sync
    umount /mnt
    sync
  done
}  

prepare_fresh_disk
mkfs.btrfs "${PARTITION}"
fuzz_mnt

prepare_fresh_disk
mkfs.ext2 "${PARTITION}"
fuzz_mnt

prepare_fresh_disk
mkfs.ext3 "${PARTITION}"
fuzz_mnt

prepare_fresh_disk
mkfs.ext4 "${PARTITION}"

prepare_fresh_disk
mkfs.jfs -q "${PARTITION}"
fuzz_mnt

prepare_fresh_disk
mkfs.ntfs "${PARTITION}"
fuzz_mnt

prepare_fresh_disk
mkfs.xfs "${PARTITION}"
fuzz_mnt
