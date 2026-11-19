FROM python:3.13-alpine@sha256:9ef1a599f863231c3d91e941389bfdc4a2d6070557243d54df1a4e57015b960e
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY server.py policy_lab.py ./
COPY static ./static
USER 65534:65534
CMD ["python", "server.py", "--bind", "0.0.0.0", "--port", "8000"]
