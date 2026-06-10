FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY app.py .
COPY templates/ templates/
COPY static/ static/
COPY k8s/ k8s/

ENV PORT=5000
ENV DEBUG=false

EXPOSE 5000

CMD ["python3", "app.py"]
