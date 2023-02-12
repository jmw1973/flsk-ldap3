FROM python:3.10.9

USER 0

COPY app /app
WORKDIR /app

COPY requirements.txt ./

RUN mkdir -p /root/.ssh && chmod 0700 /root/.ssh/
COPY keys/id_rsa /root/.ssh/
COPY keys/id_rsa.pub /root/.ssh/
RUN chown -R root:root /root/.ssh && chmod 0600 /root/.ssh/id_rsa && chmod 0600 /root/.ssh/id_rsa.pub
RUN echo "Host remotehost\n\tStrictHostKeyChecking no\n" >> /root/.ssh/config

RUN apt-get update
RUN apt-get install -y vim git
RUN python3 -m pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "main:app", "--access-logfile=-"]
