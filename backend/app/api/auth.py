from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.models.database import get_db
from backend.app.models.entities import User
from backend.app.schemas.auth import UserCreateSchema, UserLoginSchema, TokenSchema, UserResponseSchema
from backend.app.services.auth_service import hash_password, verify_password, create_access_token, get_current_user

router = APIRouter(prefix="/api/auth", tags=["auth"])

@router.post("/register", response_model=UserResponseSchema, status_code=status.HTTP_201_CREATED)
def register(user_data: UserCreateSchema, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user_data.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists"
        )
    user = User(
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name or "Security Analyst",
        role=user_data.role or "Analyst"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserResponseSchema(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active
    )

@router.post("/login", response_model=TokenSchema)
def login(login_data: UserLoginSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_data.email).first()
    if not user or not verify_password(login_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    token = create_access_token({"sub": user.id, "email": user.email, "role": user.role})
    return TokenSchema(
        access_token=token,
        token_type="bearer",
        user_id=user.id,
        email=user.email,
        full_name=user.full_name or "Security Analyst",
        role=user.role or "Analyst"
    )

@router.get("/me", response_model=UserResponseSchema)
def get_me(user: User = Depends(get_current_user)):
    if not user:
        # Fallback default analyst session for effortless demo
        return UserResponseSchema(
            id="analyst-demo-01",
            email="analyst@cybertwin.org",
            full_name="Lead CyberTwin Analyst",
            role="Analyst",
            is_active=True
        )
    return UserResponseSchema(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active
    )

