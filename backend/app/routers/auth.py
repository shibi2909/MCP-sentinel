"""Dashboard login (JWT) and current-user info."""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import User
from app.security.audit import append_audit
from app.security.auth import ROLE_PERMISSIONS, create_access_token, get_current_user, verify_password

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(body: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.username == body.username))
    if user is None or not user.is_active or not verify_password(body.password, user.password_hash):
        append_audit(db, event_type="USER_LOGIN", actor=body.username[:64], action="DENIED", details={"reason": "invalid credentials"})
        # Same message for unknown user and wrong password: do not reveal which usernames exist.
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
    append_audit(db, event_type="USER_LOGIN", actor=user.username, action="SUCCESS", details={"role": user.role})
    return {"access_token": create_access_token(user), "token_type": "bearer",
            "user": {"username": user.username, "role": user.role, "permissions": sorted(ROLE_PERMISSIONS[user.role])}}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"username": user.username, "role": user.role, "permissions": sorted(ROLE_PERMISSIONS[user.role])}
