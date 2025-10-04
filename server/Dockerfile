FROM python:3.12-slim

WORKDIR /app

COPY server.py /app/server.py

EXPOSE 12345

ENV TZ=Asia/Shanghai

CMD ["python", "server.py"]
