FROM ghcr.io/srl-labs/vrnetlab-base@sha256:57f36ae1cf44a78a6b2cad35a6276565c56edfd28e8160ae9a772929db28fd6d

RUN apt-get update -qy \
    && apt-get install -y --no-install-recommends openvswitch-switch dos2unix curl \
    && rm -rf /var/lib/apt/lists/*

ARG IMAGE=fortios.qcow2
COPY common /common
COPY launch.py /
COPY ${IMAGE} /
COPY launcher.py /launcher.py
COPY lab-entrypoint.sh /lab-entrypoint.sh
RUN chmod 0755 /launcher.py /lab-entrypoint.sh

EXPOSE 22 161/udp 830 5000 10000-10099 3443 80 443
HEALTHCHECK --interval=30s --timeout=240s --retries=3 \
    CMD ["uv", "run", "/common/fos_healthcheck.py"]

ENTRYPOINT ["/lab-entrypoint.sh"]
