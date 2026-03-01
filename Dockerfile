FROM python:3.12-slim
RUN pip install --no-cache-dir cryptography
COPY materialize.py /app/materialize.py
WORKDIR /app
ENTRYPOINT ["python3", "materialize.py"]
