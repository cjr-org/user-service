from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
)
from src.extensions import db, bcrypt
from src.models.user import User

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


@auth_bp.route("/register", methods=["POST"])
def register():
      """Register a new user account."""
      data = request.get_json()
      if not data:
                return jsonify({"error": "Request body must be JSON"}), 400

      required = ["email", "username", "password"]
      missing = [f for f in required if not data.get(f)]
      if missing:
                return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 422

      if User.query.filter_by(email=data["email"]).first():
                return jsonify({"error": "Email already registered"}), 409

      if User.query.filter_by(username=data["username"]).first():
                return jsonify({"error": "Username already taken"}), 409

      password_hash = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
      user = User(
          email=data["email"],
          username=data["username"],
          password_hash=password_hash,
          first_name=data.get("first_name"),
          last_name=data.get("last_name"),
      )
      db.session.add(user)
      db.session.commit()

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    return (
              jsonify(
                            {
                                              "user": user.to_dict(),
                                              "access_token": access_token,
                                              "refresh_token": refresh_token,
                            }
              ),
              201,
    )


@auth_bp.route("/login", methods=["POST"])
def login():
      """Authenticate a user and return JWT tokens."""
      data = request.get_json()
      if not data:
                return jsonify({"error": "Request body must be JSON"}), 400

      email = data.get("email")
      password = data.get("password")
      if not email or not password:
                return jsonify({"error": "Email and password are required"}), 422

      user = User.query.filter_by(email=email).first()
      if not user or not bcrypt.check_password_hash(user.password_hash, password):
                return jsonify({"error": "Invalid email or password"}), 401

      if not user.is_active:
                return jsonify({"error": "Account is deactivated"}), 403

      user.last_login_at = datetime.now(timezone.utc)
      db.session.commit()

    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)

    return jsonify(
              {
                            "user": user.to_dict(),
                            "access_token": access_token,
                            "refresh_token": refresh_token,
              }
    )


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
      """Issue a new access token using a valid refresh token."""
      user_id = get_jwt_identity()
      access_token = create_access_token(identity=user_id)
      return jsonify({"access_token": access_token})


@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def me():
      """Return the currently authenticated user's profile."""
      user_id = get_jwt_identity()
      user = User.query.get(user_id)
      if not user:
                return jsonify({"error": "User not found"}), 404
            return jsonify({"user": user.to_dict()})
