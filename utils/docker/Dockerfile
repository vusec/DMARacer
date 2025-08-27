FROM ubuntu:24.04 AS base

ARG DEBIAN_FRONTEND=noninteractive
# libclang-dev, coq and ocaml is for Creal
RUN apt-get update  && \
    apt-get install -y sudo fish zsh nano vim \
    cmake g++ clang-14 wget git m4 ninja-build build-essential \
    build-essential lld-14 libelf-dev qemu-system-x86 bison \
    flex golang libssl-dev debootstrap python3-pexpect socat \
    ccache qemu-system-arm qemu-user-static \
    python3-pip libslirp-dev iperf curl cpio libglib2.0-dev pkg-config \
    libgtk-3-dev rsync bc iproute2

RUN userdel -r ubuntu && useradd dmaracer -u 1000 -m -s /bin/bash && echo "dmaracer ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

ENV XDG_DATA_HOME=/home/dmaracer/mnt/cache/xdg_home
USER dmaracer
ENV PATH="$PATH:/home/dmaracer/.local/bin/"
RUN pip3 install --break-system-packages --user vncdotool psutil go-task-bin tqdm pymongo tabulate

RUN git config --global --add safe.directory '*' && \
    git config --global user.email "dmaracer@dma.racer" && \
    git config --global user.name "DMARacer Container" && \
    git config --global advice.detachedHead false
