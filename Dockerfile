# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Development image for the SCITT selective-disclosure demo.

FROM mcr.microsoft.com/azurelinux/base/core:3.0

ARG SHELLCHECK_VERSION=0.11.0
ARG SHELLCHECK_SHA256=8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198
ARG BIOME_VERSION=2.5.12
ARG BIOME_SHA256=e2475688799c9e78dd25ba5cf676676ffe74caf182a35082b1d22039151fdf63

RUN tdnf -y update && \
        tdnf -y install --disablerepo azurelinux-official-ms-non-oss \
            build-essential ca-certificates cmake curl git gnupg2 jq ninja-build \
            nodejs procps python3 python3-pip rpm-build tar util-linux xz zstd && \
        curl -fsSL \
            "https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.linux.x86_64.tar.xz" \
            -o /tmp/shellcheck.tar.xz && \
        echo "${SHELLCHECK_SHA256}  /tmp/shellcheck.tar.xz" | sha256sum -c - && \
        tar -xJf /tmp/shellcheck.tar.xz -C /tmp && \
        install -m 0755 "/tmp/shellcheck-v${SHELLCHECK_VERSION}/shellcheck" /usr/local/bin/shellcheck && \
        curl -fsSL \
            "https://github.com/biomejs/biome/releases/download/%40biomejs%2Fbiome%40${BIOME_VERSION}/biome-linux-x64" \
            -o /tmp/biome && \
        echo "${BIOME_SHA256}  /tmp/biome" | sha256sum -c - && \
        install -m 0755 /tmp/biome /usr/local/bin/biome && \
        rm -rf /tmp/biome /tmp/shellcheck* && \
    tdnf clean all

WORKDIR /workspace

CMD ["/bin/bash"]
