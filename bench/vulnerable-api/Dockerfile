FROM python:3.8.1-slim
WORKDIR /usr/src/app
COPY openapi ./openapi
COPY requirements.txt .
COPY vAPI.py .
COPY vAPI.db .
RUN pip install --no-cache-dir -r requirements.txt
EXPOSE 8081
CMD [ "python", "./vAPI.py" ]

