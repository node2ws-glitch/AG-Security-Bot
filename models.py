from datetime import datetime, timezone
from sqlalchemy import String, DateTime, Boolean, Text, Index
from sqlalchemy.orm import Mapped, mapped_column
from database import Base

def utcnow():
    return datetime.now(timezone.utc)

class License(Base):
    __tablename__ = "licenses"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(120), default="default")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

class SecurityEvent(Base):
    __tablename__ = "security_events"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    guild_id: Mapped[str] = mapped_column(String(32), default="DM")
    actor_id: Mapped[str] = mapped_column(String(32), default="unknown")
    command: Mapped[str] = mapped_column(String(80))
    outcome: Mapped[str] = mapped_column(String(40), default="ok")
    details: Mapped[str] = mapped_column(Text, default="")
Index("ix_events_created_command", SecurityEvent.created_at, SecurityEvent.command)
