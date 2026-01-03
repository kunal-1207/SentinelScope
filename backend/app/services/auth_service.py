from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from passlib.context import CryptContext

from app.models.user import User
from app.schemas.user import UserCreate, UserResponse


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AuthService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def authenticate_user(self, username: str, password: str) -> Optional[UserResponse]:
        """Authenticate a user by username and password"""
        result = await self.db.execute(select(User).where(User.username == username))
        user = result.scalar_one_or_none()
        
        if not user or not self.verify_password(password, user.hashed_password):
            return None
        
        return UserResponse.from_orm(user)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against a hashed password"""
        return pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str) -> str:
        """Hash a plain password"""
        return pwd_context.hash(password)

    async def create_user(self, user_data: UserCreate) -> Optional[UserResponse]:
        """Create a new user"""
        # Check if user already exists
        result = await self.db.execute(
            select(User).where((User.username == user_data.username) | (User.email == user_data.email))
        )
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            return None
        
        # Hash the password
        hashed_password = self.get_password_hash(user_data.password)
        
        # Create the user
        db_user = User(
            username=user_data.username,
            email=user_data.email,
            full_name=user_data.full_name,
            hashed_password=hashed_password
        )
        
        self.db.add(db_user)
        await self.db.commit()
        await self.db.refresh(db_user)
        
        return UserResponse.from_orm(db_user)