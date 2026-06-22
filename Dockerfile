# Copyright (c) Microsoft Corporation. All rights reserved.
# Dev image for building CCF (from source) and the selective-disclosure app.
#
# This image contains ONLY the toolchain / dependencies. The source code
# (CCF submodule + app) is bind-mounted at runtime so you edit on the host
# and build inside the container. See docker/dev.sh.

FROM mcr.microsoft.com/azurelinux/base/core:3.0

# Install the CCF build + dev toolchain using CCF's own setup scripts so the
# environment exactly matches what CCF expects. Only the scripts are copied in;
# the rest of the source is mounted at runtime.
COPY third_party/CCF/scripts/setup-ci.sh /tmp/ccf-scripts/setup-ci.sh
COPY third_party/CCF/scripts/setup-dev.sh /tmp/ccf-scripts/setup-dev.sh

RUN tdnf -y update && \
    tdnf -y install ca-certificates git tar && \
    bash /tmp/ccf-scripts/setup-ci.sh && \
    bash /tmp/ccf-scripts/setup-dev.sh && \
    tdnf clean all

WORKDIR /workspace

CMD ["/bin/bash"]
