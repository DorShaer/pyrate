FROM python:3.9-slim-buster

COPY pyrate.py /app/
COPY requirements.txt /app/

RUN pip install -r /app/requirements.txt

ENTRYPOINT [ "python3", "/app/pyrate.py" ]
