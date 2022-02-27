#!/bin/bash

source env.sh

qemu-img create -f raw disk_image $SIZE
