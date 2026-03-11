from datetime import datetime
import uuid
from src.extensions import db


class User(db.Model):
      """User model for authentication and profile management."""

    __tablename__ = "users"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    first_name = db.Column(db.String(64), nullable=True)
    last_name = db.Column(db.String(64), nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    role = db.Column(db.String(32), default="user", nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
              db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )
    last_login_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
              return f"<User {self.username}>"

    def to_dict(self):
              return {
                            "id": self.id,
                            "email": self.email,
                            "username": self.username,
                            "first_name": self.first_name,
                            "last_name": self.last_name,
                            "is_active": self.is_active,
                            "is_verified": self.is_verified,
                            "role": self.role,
                            "created_at": self.created_at.isoformat(),
                            "updated_at": self.updated_at.isoformat(),
                            "last_login_at": (
                                              self.last_login_at.isoformat() if self.last_login_at else None
                            ),
              }
