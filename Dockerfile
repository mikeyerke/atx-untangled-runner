# SPDX-License-Identifier: BUSL-1.1
FROM ghcr.io/bytebot-ai/bytebot-desktop@sha256:1360480c6038bb1cb4f032c6ba93fbd2fb9ad0164fb5b50fb712dd15876ba7ba

USER root
WORKDIR /opt/atx-runner
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
RUN npx playwright install --with-deps chromium
COPY src ./src
COPY supervisor-atx.conf /etc/supervisor/conf.d/atx-runner.conf
RUN chown -R user:user /opt/atx-runner

ENV DISPLAY=:0 NODE_ENV=production
EXPOSE 8787

# The upstream image's supervisord command remains the container command. This
# additional program runs beside Xfce, Chromium, bytebotd, and noVNC.
