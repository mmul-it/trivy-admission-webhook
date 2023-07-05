FROM python:3.8-slim-buster

WORKDIR /trivy-scanner

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

RUN apt update && \
    apt-get install -y wget apt-transport-https gnupg lsb-release
RUN wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | apt-key add -
RUN echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | tee -a /etc/apt/sources.list.d/trivy.list
RUN apt update
RUN apt install -y trivy

COPY app.py .

CMD [ "python3", "app.py"]
