from sqlalchemy import Column, Integer, String, DateTime, JSON, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import json

Base = declarative_base()

class SyncStatus(Base):
    """Track sync operations in PostgreSQL"""
    __tablename__ = "sync_status"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    sync_id = Column(String(100), unique=True, index=True)  # e.g., "rtarf_sync"
    is_running = Column(Boolean, default=False, nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(50), nullable=True)  # 'running', 'success', 'error'
    result = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    lock_expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SyncHistory(Base):
    """Historical log of sync operations"""
    __tablename__ = "sync_history"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    sync_id = Column(String(100), index=True)
    started_at = Column(DateTime, nullable=False)
    completed_at = Column(DateTime, nullable=False)
    status = Column(String(50), nullable=False)
    records_fetched = Column(Integer, default=0)
    records_inserted = Column(Integer, default=0)
    records_updated = Column(Integer, default=0)
    duration_seconds = Column(Integer, nullable=True)
    result = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class DBSyncStatusManager:
    """Manage sync status using PostgreSQL"""
    
    SYNC_ID = "rtarf_sync"
    
    @staticmethod
    def acquire_lock(db: Session, timeout_minutes: int = 120) -> bool:
        """
        Acquire a database lock for sync operation
        Returns True if lock acquired, False if already locked
        """
        now = datetime.utcnow()
        lock_expires = now + timedelta(minutes=timeout_minutes)
        
        # Get or create sync status
        sync = db.query(SyncStatus).filter(
            SyncStatus.sync_id == DBSyncStatusManager.SYNC_ID
        ).first()
        
        if not sync:
            # Create new status entry
            sync = SyncStatus(
                sync_id=DBSyncStatusManager.SYNC_ID,
                is_running=True,
                started_at=now,
                status='running',
                lock_expires_at=lock_expires
            )
            db.add(sync)
            db.commit()
            return True
        
        # Check if lock is expired
        if sync.lock_expires_at and sync.lock_expires_at < now:
            # Lock expired, can take over
            sync.is_running = True
            sync.started_at = now
            sync.status = 'running'
            sync.lock_expires_at = lock_expires
            sync.error_message = None
            db.commit()
            return True
        
        # Check if already running
        if sync.is_running:
            return False
        
        # Lock available
        sync.is_running = True
        sync.started_at = now
        sync.status = 'running'
        sync.lock_expires_at = lock_expires
        sync.error_message = None
        db.commit()
        return True
    
    @staticmethod
    def release_lock(db: Session, result: Optional[Dict[str, Any]] = None):
        """Release the sync lock and update status"""
        sync = db.query(SyncStatus).filter(
            SyncStatus.sync_id == DBSyncStatusManager.SYNC_ID
        ).first()
        
        if sync:
            sync.is_running = False
            sync.completed_at = datetime.utcnow()
            sync.status = result.get('status', 'unknown') if result else 'completed'
            sync.result = result
            sync.lock_expires_at = None
            
            if result and result.get('status') == 'error':
                sync.error_message = result.get('error')
            
            db.commit()
    
    @staticmethod
    def is_running(db: Session) -> bool:
        """Check if sync is currently running"""
        sync = db.query(SyncStatus).filter(
            SyncStatus.sync_id == DBSyncStatusManager.SYNC_ID
        ).first()
        
        if not sync:
            return False
        
        # Check if lock expired
        now = datetime.utcnow()
        if sync.lock_expires_at and sync.lock_expires_at < now:
            return False
        
        return sync.is_running
    
    @staticmethod
    def get_status(db: Session) -> Dict[str, Any]:
        """Get current sync status"""
        sync = db.query(SyncStatus).filter(
            SyncStatus.sync_id == DBSyncStatusManager.SYNC_ID
        ).first()
        
        if not sync:
            return {
                "is_running": False,
                "last_run": None,
                "last_result": None
            }
        
        return {
            "is_running": sync.is_running,
            "started_at": sync.started_at.isoformat() if sync.started_at else None,
            "completed_at": sync.completed_at.isoformat() if sync.completed_at else None,
            "status": sync.status,
            "result": sync.result,
            "error_message": sync.error_message,
            "lock_expires_at": sync.lock_expires_at.isoformat() if sync.lock_expires_at else None
        }
    
    @staticmethod
    def add_to_history(db: Session, result: Dict[str, Any], started_at: datetime):
        """Add sync result to history"""
        completed_at = datetime.utcnow()
        duration = int((completed_at - started_at).total_seconds())
        
        history = SyncHistory(
            sync_id=DBSyncStatusManager.SYNC_ID,
            started_at=started_at,
            completed_at=completed_at,
            status=result.get('status', 'unknown'),
            records_fetched=result.get('fetched', 0),
            records_inserted=result.get('inserted', 0),
            records_updated=result.get('updated', 0),
            duration_seconds=duration,
            result=result,
            error_message=result.get('error')
        )
        db.add(history)
        db.commit()
    
    @staticmethod
    def get_history(db: Session, limit: int = 10):
        """Get sync history"""
        history = db.query(SyncHistory).filter(
            SyncHistory.sync_id == DBSyncStatusManager.SYNC_ID
        ).order_by(SyncHistory.created_at.desc()).limit(limit).all()
        
        return [
            {
                "id": h.id,
                "started_at": h.started_at.isoformat(),
                "completed_at": h.completed_at.isoformat(),
                "status": h.status,
                "records_fetched": h.records_fetched,
                "records_inserted": h.records_inserted,
                "records_updated": h.records_updated,
                "duration_seconds": h.duration_seconds,
                "error_message": h.error_message
            }
            for h in history
        ]
    
    @staticmethod
    def force_release_lock(db: Session):
        """Emergency release of lock"""
        sync = db.query(SyncStatus).filter(
            SyncStatus.sync_id == DBSyncStatusManager.SYNC_ID
        ).first()
        
        if sync:
            sync.is_running = False
            sync.lock_expires_at = None
            db.commit()
