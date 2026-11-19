FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
    && apt-get install -y --no-install-recommends freeradius python3 \
    && rm -rf /var/lib/apt/lists/*
COPY entrypoint.py selftest.py /opt/radius/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
EXPOSE 1812/udp
ENTRYPOINT ["python3", "/opt/radius/entrypoint.py"]
