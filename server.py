from flask import Flask, request, jsonify
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import bcrypt
import secrets
import time
import os

app = Flask(__name__)
# SQLite база в файле users.db на Render
DATABASE_URL = 'sqlite:///users.db'
engine = create_engine(DATABASE_URL, echo=False)
Base = declarative_base()

# Модель пользователя
class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    name = Column(String(100), nullable=False)

# Модель для одноразовых кодов Telegram
class TelegramCode(Base):
    __tablename__ = 'telegram_codes'
    id = Column(Integer, primary_key=True)
    code = Column(String(32), unique=True, nullable=False)
    user_id = Column(Integer, nullable=False)
    expires_at = Column(Integer, nullable=False)

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    name = data.get('name')
    
    session = Session()
    if session.query(User).filter_by(email=email).first():
        session.close()
        return jsonify({'error': 'Email уже занят'}), 400
    
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    user = User(email=email, password=hashed_password, name=name)
    session.add(user)
    session.commit()
    
    # Генерация одноразового кода для Telegram
    code = secrets.token_hex(16)
    expires_at = int(time.time()) + 3600  # Код действителен 1 час
    telegram_code = TelegramCode(code=code, user_id=user.id, expires_at=expires_at)
    session.add(telegram_code)
    session.commit()
    
    session.close()
    return jsonify({
        'message': f'Пользователь {name} успешно зарегистрирован!',
        'telegram_code': f'https://t.me/MyAuthBot?start={code}'
    }), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    session = Session()
    user = session.query(User).filter_by(email=email).first()
    if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
        # Генерация одноразового кода для Telegram
        code = secrets.token_hex(16)
        expires_at = int(time.time()) + 3600
        telegram_code = TelegramCode(code=code, user_id=user.id, expires_at=expires_at)
        session.add(telegram_code)
        session.commit()
        
        session.close()
        return jsonify({
            'message': f'Вход успешен! Привет, {user.name}!',
            'telegram_code': f'https://t.me/MyAuthBot?start={code}'
        }), 200
    session.close()
    return jsonify({'error': 'Неправильный email или пароль'}), 401

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
    session.delete(telegram_code)  # Удаляем код после использования
    session.commit()
    session.close()
    return jsonify({'message': f'Аутентификация успешна! Пользователь: {user.name}'}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))