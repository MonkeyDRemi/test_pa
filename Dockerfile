FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    nodejs \
    php-cli \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml .
RUN pip install flask pyyaml rich typer gunicorn google-genai

COPY . .

EXPOSE 10000

CMD ["gunicorn", "--bind", "0.0.0.0:10000", "web_app:app"]