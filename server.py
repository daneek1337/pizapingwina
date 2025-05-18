from flask import Flask, request, jsonify
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt
import secrets
import time
import os
import uuid

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
    uid = Column(String(36), unique=True, nullable=False)

class TelegramCode(Base):
    __tablename__ = 'telegram_codes'
    id = Column(Integer, primary_key=True)
    code = Column(String(32), unique=True, nullable=False)
    user_id = Column(Integer, nullable=False)
    expires_at = Column(Integer, nullable=False)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

BOT_USERNAME = 'pizdapingwina_bot'

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
    uid = str(uuid.uuid4())
    user = User(username=username, password=hashed_password, name=name, uid=uid)
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
        'uid': uid
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
        
        # Формируем ответ до закрытия сессии
        response = {
            'message': f'Вход успешен! Привет, {user.name}!',
            'telegram_code': f'https://t.me/{BOT_USERNAME}?start={code}',
            'uid': user.uid
        }
        
        # Теперь закрываем сессию
        session.close()
        return jsonify(response), 200
    session.close()
    return jsonify({'error': 'Неправильный username или пароль'}), 401

@app.route('/verify_telegram_code', methods=['POST'])
def verify_telegram_code():
    data = request.json
    code = data.get('code')
    
    session = Session()
    telegram_code = session.query(TelegramCode).filter_by(code=code).first()
    if not telegram_code or telegram_code.expires_at < int(time.time()):
        session.close()
        return jsonify({'error': 'Код недействителен или истёк'}), 400
    
    user = session.query(User).filter_by(id=telegram_code.user_id).first()
    if not user:
        session.close()
        return jsonify({'error': 'Пользователь не найден'}), 404
    
    session.delete(telegram_code)
    session.commit()
    
    response = {
        'message': f'Аутентификация успешна! Пользователь: {user.name}',
        'uid': user.uid
    }
    
    session.close()
    return jsonify(response), 200

@app.route('/message', methods=['POST'])
def send_message():
    data = request.json
    uid = data.get('uid')
    message = data.get('message')
    
    session = Session()
    user = session.query(User).filter_by(uid=uid).first()
    if not user:
        session.close()
        return jsonify({'error': 'Пользователь с таким UID не найден'}), 404
    
    response = {
        'message': f'Сообщение для {user.name}: {message}',
        'uid': uid
    }
    
    session.close()
    return jsonify(response), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))