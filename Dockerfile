# SPDX-License-Identifier: BUSL-1.1
FROM ghcr.io/bytebot-ai/bytebot-desktop@sha256:1360480c6038bb1cb4f032c6ba93fbd2fb9ad0164fb5b50fb712dd15876ba7ba

USER root
WORKDIR /opt/atx-runner
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
RUN node node_modules/playwright-core/cli.js install --with-deps chromium

# Patch the two vulnerable transitive runtime dependencies inherited from the
# archived Bytebot desktop image. Explicit versions match Trivy fixed ranges.
RUN npm install --prefix /bytebotd --omit=dev --no-audit --no-fund \
      @xhmikosr/decompress@10.2.1 form-data@4.0.4

COPY src ./src
COPY supervisor-atx.conf /etc/supervisor/conf.d/atx-runner.conf

# The archived desktop base contains runtime-irrelevant development headers,
# USB printer discovery, and an old global npm toolchain. Remove them after the
# application and browser are installed, update remaining Ubuntu packages, and
# retain only the Node runtime required by the runner and bytebotd.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y \
    && DEBIAN_FRONTEND=noninteractive apt-get purge -y ipp-usb linux-libc-dev \
    && DEBIAN_FRONTEND=noninteractive apt-get autoremove -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /root/.npm /home/user/.npm \
      /usr/lib/node_modules/npm /usr/local/lib/node_modules/npm \
    && rm -f /usr/bin/npm /usr/bin/npx /usr/local/bin/npm /usr/local/bin/npx \
    && chown -R user:user /opt/atx-runner

ENV DISPLAY=:0 NODE_ENV=production
EXPOSE 8787

# The upstream image's supervisord command remains the container command. This
# additional program runs beside Xfce, Chromium, bytebotd, and noVNC.
