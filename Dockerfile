FROM python:3.12-alpine

RUN apk add --no-cache iputils

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY runner.py .

RUN mkdir -p /artifacts

ENTRYPOINT ["python3", "/app/runner.py"]
