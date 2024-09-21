# Use the official Python image from the Docker Hub
FROM python:3.9-alpine

RUN addgroup -S grupoapp && adduser -S appuser -G grupoapp

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chown -R appuser:grupoapp /app

USER appuser

EXPOSE 5000

CMD ["python", "src/app.py"]
