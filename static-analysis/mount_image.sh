#!/bin/bash

PASSWORD="raspberr"
IMAGE_RAW_PATH="/home/raspberry/firmware-analysis-toolkit/firmadyne/scratch/1/image.raw"
MOUNT_POINT="/home/kraspberry/firmware-analysis-toolkit/firmadyne/scratch/1/image_fs"


sudo_command() {
    echo $PASSWORD | sudo -S $@
}

mount_image() {
    sudo_command modprobe nbd
    sudo_command qemu-nbd --format=raw -c /dev/nbd0 $IMAGE_RAW_PATH
    sudo_command mkdir -p $MOUNT_POINT
    sudo_command mount /dev/nbd0p1 $MOUNT_POINT
}

unmount_image() {
    sudo_command umount $MOUNT_POINT
    sudo_command qemu-nbd -d /dev/nbd0
}

if [ "$1" == "mount" ]; then
    mount_image
elif [ "$1" == "unmount" ]; then
    unmount_image
else
    echo "Uso: $0 {mount|unmount}"
fi
