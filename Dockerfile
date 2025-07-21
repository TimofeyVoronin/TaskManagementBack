FROM python:3.12
RUN pip install --upgrade pip setuptools wheel
WORKDIR /app
COPY requirements.txt /app/
RUN pip install -r /app/requirements.txt