import uuid

from sqlalchemy import (
    Column, String, Text, DateTime, Boolean, ForeignKey,
    UniqueConstraint, CheckConstraint, Index, or_
)
from sqlalchemy.dialects.postgresql import UUID, BYTEA
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.sql import func

Base = declarative_base()





class Conversation(Base):
    __tablename__ = "conversations"
    __table_args__ = (
        UniqueConstraint("user_a", "user_b", name="uq_user_pair"),
        CheckConstraint("user_a <> user_b", name="chk_users_not_equal"),
        Index("idx_conversations_users", "user_a", "user_b"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_a = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    user_b = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    messages = relationship("Message")
    user_a_rel = relationship("User", foreign_keys=[user_a])
    user_b_rel = relationship("User", foreign_keys=[user_b])

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(Text, unique=True, nullable=False)
    public_key_cert = Column(Text, nullable=False)
    api_key_dk = Column(Text, unique=True, nullable=False)
    api_key_expires = Column(DateTime(timezone=True), nullable=True)
    api_key_created = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    sent_messages = relationship("Message")
    conversations = relationship(
        "Conversation",
        primaryjoin=or_(
            id == Conversation.user_a,
            id == Conversation.user_b
        ),
    viewonly=True)

class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (
        Index("idx_messages_conversation_time", "conversation_id", "created_at"),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    conversation_id = Column(UUID(as_uuid=True), ForeignKey("conversations.id", ondelete="CASCADE"))
    sender_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    ciphertext = Column(BYTEA, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    sender = relationship("User", back_populates="sent_messages")
    keys = relationship("MessageKey", back_populates="message", cascade="all, delete")
    conversation = relationship("Conversation", back_populates="messages")


class MessageKey(Base):
    __tablename__ = "message_keys"
    __table_args__ = (
        Index("idx_message_keys_user", "user_id"),
    )

    message_id = Column(UUID(as_uuid=True), ForeignKey("messages.id", ondelete="CASCADE"), primary_key=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    enc_key = Column(BYTEA, nullable=False)

    message = relationship("Message", back_populates="keys")
