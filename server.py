from flask import Flask, request, jsonify
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt
import secrets
import time
import os
import requests

app = Flask(__name__)
DATABASE_URL = 'sqlite:///users.db'
engine = create_engine(DATABASE_URL, echo=False)
Base = declarative_base()

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    name = Column(String(100), nullable=False)
    chat_id = Column(String(50), nullable=True)  # Telegram chat_id

class TelegramCode(Base):
    __tablename__ = 'telegram_codes'
    id = Column(Integer, primary_key=True)
    code = Column(String(32), unique=True, nullable=False)
    user_id = Column(Integer, nullable=False)
    expires_at = Column(Integer, nullable=False)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

BOT_USERNAME = 'pizdapingwina_bot'
BOT_TOKEN = 'твой_токен_бота'  # Замени на токен @pizdapingwina_bot

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    name = data.get('name')
    
    session = Session()
    if session.query(User).filter_by(username=username).first():
        session.close()
        return jsonify({'error': 'Username уже занят'}), 400
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = User(username=username, password=hashed_password, name=name)
    session.add(user)
    session.commit()
    
    code = secrets.token_hex(16)
    expires_at = int(time.time()) + 3600
    telegram_code = TelegramCode(code=code, user_id=user.id, expires_at=expires_at)
    session.add(telegram_code)
    session.commit()
    
    response = {
        'message': f'Пользователь {name} успешно зарегистрирован!',
        'telegram_code': f'https://t.me/{BOT_USERNAME}?start={code}',
        'username': username
    }
    
    session.close()
    return jsonify(response), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    session = Session()
    user = session.query(User).filter_by(username=username).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        code = secrets.token_hex(16)
        expires_at = int(time.time()) + 3600
        telegram_code = TelegramCode(code=code, user_id=user.id, expires_at=expires_at)
        session.add(telegram_code)
        session.commit()
        
        response = {
            'message': f'Вход успешен! Привет, {user.name}!',
            'telegram_code': f'https://t.me/{BOT_USERNAME}?start={code}',
            'username': user.username
        }
        
        session.close()
        return jsonify(response), 200
    session.close()
    return jsonify({'error': 'Неправильный username или пароль'}), 401

@app.route('/verify_telegram_code', methods=['POST'])
def verify_telegram_code():
    data = request.json
    code = data.get('code')
    chat_id = data.get('chat_id')
    
    session = Session()
    telegram_code = session.query(TelegramCode).filter_by(code=code).first()
    if not telegram_code or telegram_code.expires_at < int(time.time()):
        session.close()
        return jsonify({'error': 'Код недействителен или истёк'}), 400
    
    user = session.query(User).filter_by(id=telegram_code.user_id).first()
    if not user:
        session.close()
        return jsonify({'error': 'Пользователь не найден'}), 404
    
    user.chat_id = str(chat_id)
    session.delete(telegram_code)
    session.commit()
    
    response = {
        'message': f'Аутентификация успешна! Пользователь: {user.name}',
        'username': user.username
    }
    
    session.close()
    return jsonify(response), 200

@app.route('/message', methods=['POST'])
def send_message():
    data = request.json
    username = data.get('username')
    message = data.get('message')
    
    session = Session()
    user = session.query(User).filter_by(username=username).first()
    if not user:
        session.close()
        return jsonify({'error': 'Пользователь с таким username не найден'}), 404
    
    if not user.chat_id:
        session.close()
        return jsonify({'error': 'Пользователь не подтвердил Telegram'}), 400
    
    # Отправляем сообщение в ЛС через Telegram
    try:
        telegram_response = requests.get(
            f'https://api.telegram.org/bot{BOT_TOKEN}/sendMessage',
            params={
                'chat_id': user.chat_id,
                'text': f'Новое сообщение: {message}'
            }
        )
        if telegram_response.status_code != 200:
            session.close()
            return jsonify({'error': 'Ошибка отправки сообщения в Telegram'}), 500
    except Exception as e:
        session.close()
        return jsonify({'error': f'Ошибка отправки в Telegram: {str(e)}'}), 500
    
    response = {
        'message': f'Сообщение для {user.name}: {message} отправлено в Telegram',
        'username': username
    }
    
    session.close()
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))