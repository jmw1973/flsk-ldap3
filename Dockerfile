FROM python:3.10.9

USER 0

COPY app/* /app/
WORKDIR /app

COPY requirements.txt ./

RUN apt-get update
RUN apt-get install -y vim
RUN python3 -m pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "wsgi:app", "--access-logfile=-"]
