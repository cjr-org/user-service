from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from src.extensions import db
from src.models.user import User

users_bp = Blueprint("users", __name__, url_prefix="/users")


def _require_self_or_admin(user_id):
      """Return (current_user, error_response) tuple. Error is None if authorized."""
      caller_id = get_jwt_identity()
      caller = User.query.get(caller_id)
      if not caller:
                return None, (jsonify({"error": "Authenticated user not found"}), 404)
            if caller.id != user_id and caller.role != "admin":
                      return None, (jsonify({"error": "Forbidden"}), 403)
                  return caller, None


@users_bp.route("", methods=["GET"])
@jwt_required()
def list_users():
      """List all users (admin only)."""
    caller_id = get_jwt_identity()
    caller = User.query.get(caller_id)
    if not caller or caller.role != "admin":
              return jsonify({"error": "Forbidden"}), 403

    page = request.args.get("page", 1, type=int)
    per_page = min(request.args.get("per_page", 20, type=int), 100)
    pagination = User.query.order_by(User.created_at.desc()).paginate(
              page=page, per_page=per_page, error_out=False
    )
    return jsonify(
              {
                            "users": [u.to_dict() for u in pagination.items],
                            "total": pagination.total,
                            "page": pagination.page,
                            "pages": pagination.pages,
              }
    )


@users_bp.route("/<string:user_id>", methods=["GET"])
@jwt_required()
def get_user(user_id):
      """Get a single user by ID."""
    _, err = _require_self_or_admin(user_id)
    if err:
              return err

    user = User.query.get(user_id)
    if not user:
              return jsonify({"error": "User not found"}), 404
          return jsonify({"user": user.to_dict()})


@users_bp.route("/<string:user_id>", methods=["PATCH"])
@jwt_required()
def update_user(user_id):
      """Update profile fields for a user."""
    _, err = _require_self_or_admin(user_id)
    if err:
              return err

    user = User.query.get(user_id)
    if not user:
              return jsonify({"error": "User not found"}), 404

    data = request.get_json() or {}
    allowed = {"first_name", "last_name", "username"}
    for field in allowed:
              if field in data:
                            if field == "username" and data[field] != user.username:
                                              if User.query.filter_by(username=data[field]).first():
                                                                    return jsonify({"error": "Username already taken"}), 409
                                                            setattr(user, field, data[field])

                    db.session.commit()
    return jsonify({"user": user.to_dict()})


@users_bp.route("/<string:user_id>", methods=["DELETE"])
@jwt_required()
def deactivate_user(user_id):
      """Soft-delete a user by setting is_active=False."""
    _, err = _require_self_or_admin(user_id)
    if err:
              return err

    user = User.query.get(user_id)
    if not user:
              return jsonify({"error": "User not found"}), 404

    user.is_active = False
    db.session.commit()
    return jsonify({"message": f"User {user.username} has been deactivated"}), 200


@users_bp.route("/<string:user_id>/password", methods=["PUT"])
@jwt_required()
def change_password(user_id):
      """Change a user's password."""
    from src.extensions import bcrypt

    caller, err = _require_self_or_admin(user_id)
    if err:
              return err

    user = User.query.get(user_id)
    if not user:
              return jsonify({"error": "User not found"}), 404

    data = request.get_json() or {}
    new_password = data.get("new_password")
    if not new_password or len(new_password) < 8:
              return jsonify({"error": "new_password must be at least 8 characters"}), 422

    # Non-admins must supply current password
    if caller.id == user_id:
              current_password = data.get("current_password")
        if not current_password or not bcrypt.check_password_hash(
                      user.password_hash, current_password
        ):
                      return jsonify({"error": "Current password is incorrect"}), 401

    user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
    db.session.commit()
    return jsonify({"message": "Password updated successfully"})
