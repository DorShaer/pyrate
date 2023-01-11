FROM python:3.11-slim-buster

COPY pyrate.py /app/
COPY requirements.txt /app/
COPY lib /app/lib


RUN python3 -m pip install --upgrade pip
RUN pip install -r /app/requirements.txt

ENTRYPOINT [ "python3", "/app/pyrate.py" ]
