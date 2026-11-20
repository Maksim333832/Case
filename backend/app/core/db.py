from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from app.config import get_settings


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class WorkflowORM(Base):
    __tablename__ = "workflows"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    graph_json: Mapped[str] = mapped_column(Text, nullable=False)
    is_template: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class RunORM(Base):
    __tablename__ = "runs"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    workflow_id: Mapped[str] = mapped_column(String(64), ForeignKey("workflows.id", ondelete="CASCADE"), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    trigger: Mapped[str] = mapped_column(String(64), nullable=False, default="manual")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    summary_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    ai_report_json: Mapped[str | None] = mapped_column(Text, nullable=True)


class NodeRunORM(Base):
    __tablename__ = "node_runs"
    __table_args__ = (UniqueConstraint("run_id", "node_id", name="uq_node_runs_run_node"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), ForeignKey("runs.id", ondelete="CASCADE"), nullable=False, index=True)
    node_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    output_preview_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class CredentialORM(Base):
    __tablename__ = "credentials"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False, unique=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    encrypted_value: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class UploadORM(Base):
    __tablename__ = "uploads"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class AppSettingORM(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(120), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    is_secret: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


_engine = None
_SessionLocal = None


def configure_database(database_url: str | None = None):
    global _engine, _SessionLocal
    url = database_url or get_settings().database_url
    if url.startswith("sqlite:///"):
        db_file = url[len("sqlite:///"):]
        if db_file and db_file != ":memory:":
            Path(db_file).parent.mkdir(parents=True, exist_ok=True)

    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    _engine = create_engine(url, connect_args=connect_args, future=True)

    if url.startswith("sqlite"):
        @event.listens_for(_engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, _connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.close()

    _SessionLocal = sessionmaker(bind=_engine, autoflush=False, autocommit=False, expire_on_commit=False)
    return _engine


def init_db(database_url: str | None = None) -> None:
    engine = configure_database(database_url)
    Base.metadata.create_all(bind=engine)


def get_session_factory() -> sessionmaker[Session]:
    if _SessionLocal is None:
        init_db()
    assert _SessionLocal is not None
    return _SessionLocal


def get_db() -> Generator[Session, None, None]:
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
