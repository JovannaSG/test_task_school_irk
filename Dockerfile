# Используем официальный легковесный образ Python
FROM python:3.11-slim

# Устанавливаем рабочую директорию внутри контейнера
WORKDIR /app

# Запрещаем Python писать файлы .pyc на диск (полезно для Docker)
ENV PYTHONDONTWRITEBYTECODE 1
# Запрещаем буферизацию stdout и stderr, чтобы логи сразу шли в консоль
ENV PYTHONUNBUFFERED 1

# Копируем файл зависимостей
COPY requirements.txt .

# Устанавливаем зависимости без кэширования, чтобы уменьшить вес образа
RUN pip install --no-cache-dir -r requirements.txt

# Копируем все остальные файлы проекта (app.py, папки templates и static)
COPY . .

# Сообщаем, что приложение будет работать на порту 8000
EXPOSE 8000

# Команда для запуска сервера при старте контейнера
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]