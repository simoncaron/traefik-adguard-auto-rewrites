FROM python:3.13-slim

WORKDIR /usr/src/app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY traefik_adguard_auto_rewrites.py ./

VOLUME /state

CMD [ "python", "./traefik_adguard_auto_rewrites.py" ]