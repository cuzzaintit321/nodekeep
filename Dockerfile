FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
 && useradd -u 10001 --create-home -s /usr/sbin/nologin nodekeep \
 && mkdir -p /data && chown -R nodekeep:nodekeep /data
COPY --chown=nodekeep:nodekeep app ./app
USER nodekeep
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-server-header"]
