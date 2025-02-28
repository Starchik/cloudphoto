# PhotoCloud

PhotoCloud - это удобное веб-приложение для хранения, управления и просмотра фотографий в облаке. Позволяет загружать изображения, сортировать их и быстро находить нужные снимки с помощью встроенного поиска. Сервер разворачивается у вас на компьютере. Так-же есть Android приложение для отправки фото на сервер. 

APK: [photocloud-0.1-arm64-v8a_armeabi-v7a](https://docs.google.com/uc?export=download&id=1FtKHD1hFph_0YWWuc0IgFrZ8nBVoiUTv)

![Image alt](https://github.com/Starchik/cloudphoto/blob/main/1.png)

## Demo
[Live Demo](https://cphoto.pp.ua/)

**Login:** demo@demo.com  
**Password:** demo  

---

## Возможности
- Регистрация и авторизация пользователей
- Загрузка и хранение фотографий в облаке
- Поиск изображений по названию и тегам
- Поддержка форматов: JPEG, PNG, GIF, HEIC
- Удобный и современный интерфейс на основе Bootstrap 5
- Адаптивный дизайн для работы на мобильных устройствах и ПК

---

## Установка

### 1. Установите Python 3.12.5
Скачайте и установите последнюю версию Python 3.12.5 по ссылке:  
[Python 3.12.5 (64-bit)](https://www.python.org/ftp/python/3.12.5/python-3.12.5-amd64.exe)

Во время установки **не забудьте отметить галочку** "Add Python to PATH".

---

### 2. Установите Microsoft Visual C++ Redistributable
Скачайте и установите последнюю версию Microsoft Visual C++ Redistributable (x64):  
[VC Redist x64](https://aka.ms/vs/17/release/vc_redist.x64.exe)

---

### 3. Скачайте и перейдите в папку с проектом
Откройте терминал (cmd, PowerShell или терминал в VS Code) и выполните команду:
```sh
cd PhotoCloud
```
Пример, если проект находится на рабочем столе:
```sh
cd C:\Users\pc\Desktop\PhotoCloud
```

---

### 4. Установите зависимости
Для установки всех необходимых пакетов выполните команду:
```sh
pip install -r requirements.txt
```

---

## Запуск проекта
После установки всех зависимостей запустите сервер с помощью команды:
```sh
python photo.py
```
По умолчанию сервер запустится на `http://127.0.0.1:5000/`.  
Откройте этот адрес в браузере, чтобы начать работу с PhotoCloud.

---

## Структура проекта
```
PhotoCloud/
│── instance/             # Папка с базой данных
│── templates/            # HTML-шаблоны
│── uploads/              # Загруженные пользователями файлы
│── photo.py              # Основной файл приложения
│── requirements.txt      # Список зависимостей
│── README.md             # Данный файл
```

---

## Используемые технологии
- **Flask** - основной фреймворк для разработки веб-приложения
- **Bootstrap 5** - стилизация интерфейса
- **SQLite** - база данных для хранения информации о пользователях и фотографиях
- **Werkzeug & Flask-Login** - управление авторизацией пользователей

---

## Контакты
Если у вас возникли вопросы или предложения, вы можете связаться со мной:
📧 Email: Starchik1@protonmail.com

