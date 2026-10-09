"""
auth_utils.py — JWT identity → User row helper.

Flask-Login's `current_user` was a lazily-loaded proxy that resolved to a
full User row automatically. Flask-JWT-Extended's get_jwt_identity() only
gives back the identity string stored in the token (the user's id) — every
route that used to read `current_user` now has to load that row itself.
This wraps that lookup in one place so routes stay a one-line swap:

    current_user.id            ->   get_current_user().id
    @login_required             ->   @jwt_required()

get_current_user() is safe to call any time — with @jwt_required(), with
jwt_required(optional=True), or with no JWT verification having run at
all in this request (e.g. a CORS preflight OPTIONS request hitting
auth.py's before_app_request hook). flask_jwt_extended's get_jwt() raises
RuntimeError — not just a None identity — when optional=True verification
ran but found no token at all, so that case is caught here too; this
always just returns None rather than ever raising.
"""
from flask_jwt_extended import get_jwt_identity

from models import User, db


def get_current_user():
    """Return the User row for the requesting JWT's identity, or None."""
    try:
        uid = get_jwt_identity()
    except RuntimeError:
        return None
    if uid is None:
        return None
    try:
        return db.session.get(User, int(uid))
    except (TypeError, ValueError):
        return None
