FROM python:3.12-slim
RUN pip install --no-cache-dir cryptography
RUN mkdir -p /output && chown 1000:1000 /output
COPY materialize.py /app/materialize.py
WORKDIR /app
USER 1000:1000
ENTRYPOINT ["python3", "materialize.py"]
