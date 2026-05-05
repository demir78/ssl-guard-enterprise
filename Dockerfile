FROM python:3.9-slim

# İşletim sistemi güncellemeleri ve whois paketinin kurulumu
RUN apt-get update && apt-get install -y whois tzdata

# Zaman dilimini Türkiye olarak ayarla (Loglar için önemli)
ENV TZ="Europe/Istanbul"

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
