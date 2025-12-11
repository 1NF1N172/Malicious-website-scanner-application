# models.py

from extensions import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model, UserMixin):
    __tablename__ = 'users'  # Optional: таблицата в базата
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(200), nullable=False)

    # Password свойства
    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute.')

    # Password задаване
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    # Password верификация
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
