"""
CYBERSPLOI Authentication Service
Handles user registration, login, JWT token generation
"""

from datetime import datetime, timedelta
from typing import Optional, Tuple
import jwt
import bcrypt
from sqlalchemy.orm import Session
from models import User, UserTier
from pydantic import EmailStr

class AuthenticationService:
    """Authentication and user management service"""
    
    def __init__(self, secret_key: str, jwt_algorithm: str = "HS256", jwt_expiration_hours: int = 24):
        self.secret_key = secret_key
        self.jwt_algorithm = jwt_algorithm
        self.jwt_expiration_hours = jwt_expiration_hours
    
    # ========================================================================
    # PASSWORD MANAGEMENT
    # ========================================================================
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    
    # ========================================================================
    # TOKEN MANAGEMENT
    # ========================================================================
    
    def create_access_token(self, user_id: str, email: str) -> Tuple[str, datetime]:
        """Generate JWT access token"""
        expiration = datetime.utcnow() + timedelta(hours=self.jwt_expiration_hours)
        
        payload = {
            "user_id": user_id,
            "email": email,
            "exp": expiration,
            "iat": datetime.utcnow()
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.jwt_algorithm)
        return token, expiration
    
    def verify_token(self, token: str) -> Optional[dict]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.jwt_algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def create_refresh_token(self, user_id: str) -> str:
        """Create refresh token (longer expiration)"""
        expiration = datetime.utcnow() + timedelta(days=30)
        
        payload = {
            "user_id": user_id,
            "type": "refresh",
            "exp": expiration,
            "iat": datetime.utcnow()
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.jwt_algorithm)
    
    # ========================================================================
    # USER REGISTRATION
    # ========================================================================
    
    def register_user(
        self,
        db: Session,
        email: EmailStr,
        password: str,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        company: Optional[str] = None
    ) -> Tuple[Optional[User], Optional[str]]:
        """Register new user"""
        
        # Check if user exists
        existing_user = db.query(User).filter(User.email == email).first()
        if existing_user:
            return None, "Email already registered"
        
        # Validate password strength
        if len(password) < 12:
            return None, "Password must be at least 12 characters"
        
        # Check password requirements
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password)
        
        if not (has_upper and has_digit and has_special):
            return None, "Password must contain uppercase, digit, and special character"
        
        # Create user
        user = User(
            email=email,
            password_hash=self.hash_password(password),
            first_name=first_name,
            last_name=last_name,
            company=company,
            tier=UserTier.FREE,
            is_active=True
        )
        
        db.add(user)
        db.commit()
        db.refresh(user)
        
        return user, None
    
    # ========================================================================
    # USER LOGIN
    # ========================================================================
    
    def authenticate_user(
        self,
        db: Session,
        email: str,
        password: str
    ) -> Tuple[Optional[User], Optional[str]]:
        """Authenticate user and return user object"""
        
        user = db.query(User).filter(User.email == email).first()
        
        if not user:
            return None, "Invalid email or password"
        
        if not user.is_active:
            return None, "Account is inactive"
        
        if not self.verify_password(password, user.password_hash):
            return None, "Invalid email or password"
        
        # Update last login
        user.last_login = datetime.utcnow()
        db.commit()
        
        return user, None
    
    # ========================================================================
    # PASSWORD RESET
    # ========================================================================
    
    def initiate_password_reset(self, db: Session, email: str) -> Tuple[bool, str]:
        """Initiate password reset for user"""
        
        user = db.query(User).filter(User.email == email).first()
        
        if not user:
            # Don't reveal if email exists
            return True, "If email exists, reset link sent"
        
        # Generate reset token
        reset_token = self.create_refresh_token(user.id)
        user.verification_token = reset_token
        db.commit()
        
        # In real app, send email with reset link
        return True, f"Reset link sent to {email}"
    
    def reset_password(
        self,
        db: Session,
        reset_token: str,
        new_password: str
    ) -> Tuple[bool, str]:
        """Reset user password using reset token"""
        
        payload = self.verify_token(reset_token)
        if not payload:
            return False, "Invalid or expired reset token"
        
        user = db.query(User).filter(User.id == payload["user_id"]).first()
        if not user:
            return False, "User not found"
        
        # Validate new password
        if len(new_password) < 12:
            return False, "Password must be at least 12 characters"
        
        # Update password
        user.password_hash = self.hash_password(new_password)
        user.verification_token = None
        db.commit()
        
        return True, "Password reset successful"
    
    # ========================================================================
    # ACCOUNT MANAGEMENT
    # ========================================================================
    
    def get_user_by_id(self, db: Session, user_id: str) -> Optional[User]:
        """Get user by ID"""
        return db.query(User).filter(User.id == user_id).first()
    
    def get_user_by_email(self, db: Session, email: str) -> Optional[User]:
        """Get user by email"""
        return db.query(User).filter(User.email == email).first()
    
    def update_user(
        self,
        db: Session,
        user_id: str,
        **kwargs
    ) -> Optional[User]:
        """Update user information"""
        
        user = self.get_user_by_id(db, user_id)
        if not user:
            return None
        
        # Only allow certain fields to be updated
        allowed_fields = {
            'first_name', 'last_name', 'company', 'phone'
        }
        
        for key, value in kwargs.items():
            if key in allowed_fields:
                setattr(user, key, value)
        
        db.commit()
        db.refresh(user)
        
        return user
    
    def change_password(
        self,
        db: Session,
        user_id: str,
        old_password: str,
        new_password: str
    ) -> Tuple[bool, str]:
        """Change user password"""
        
        user = self.get_user_by_id(db, user_id)
        if not user:
            return False, "User not found"
        
        # Verify old password
        if not self.verify_password(old_password, user.password_hash):
            return False, "Current password is incorrect"
        
        # Validate new password
        if len(new_password) < 12:
            return False, "New password must be at least 12 characters"
        
        # Update password
        user.password_hash = self.hash_password(new_password)
        db.commit()
        
        return True, "Password changed successfully"
    
    # ========================================================================
    # SUBSCRIPTION MANAGEMENT
    # ========================================================================
    
    def upgrade_subscription(
        self,
        db: Session,
        user_id: str,
        new_tier: UserTier,
        subscription_duration_days: int = 30
    ) -> Tuple[bool, str]:
        """Upgrade user subscription"""
        
        user = self.get_user_by_id(db, user_id)
        if not user:
            return False, "User not found"
        
        user.tier = new_tier
        user.subscription_active = True
        user.subscription_expires = datetime.utcnow() + timedelta(days=subscription_duration_days)
        db.commit()
        
        return True, f"Upgraded to {new_tier.value}"
    
    def check_subscription_valid(self, db: Session, user_id: str) -> bool:
        """Check if user subscription is valid"""
        
        user = self.get_user_by_id(db, user_id)
        if not user:
            return False
        
        if not user.subscription_active:
            return user.tier == UserTier.FREE
        
        return datetime.utcnow() < user.subscription_expires
