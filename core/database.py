import sqlite3
import logging
import asyncio
from datetime import datetime, timedelta
from core.config import Config
from core.exceptions import DatabaseError

logger = logging.getLogger(__name__)

class VanguardDatabase:
    """Pro Max DB Engine: Memory-Safe, Crash-Resistant, and High-Throughput."""
    
    def __init__(self, db_path=None):
        self.db_path = db_path or Config.DATABASE_PATH
        self.is_running = True
        self.writer_task = None
        self._write_queue = None
        self._setup()

    @property
    def write_queue(self):
        """Lazy initialization of the queue to avoid loop issues during import."""
        if self._write_queue is None:
            self._write_queue = asyncio.Queue(maxsize=Config.DB_QUEUE_MAX_SIZE)
        return self._write_queue

    def _ensure_writer_started(self):
        """Starts the background writer if it's not already running."""
        if self.writer_task is None:
            try:
                self.writer_task = asyncio.create_task(self._background_writer())
            except RuntimeError:
                # No loop running yet, that's fine if we are just importing
                pass

    def _get_connection(self):
        try:
            conn = sqlite3.connect(self.db_path, timeout=30)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as e:
            logger.error(f"DB Connection Error: {e}")
            raise DatabaseError(f"Could not connect to database: {e}")

    def _setup(self):
        """Initialize schema with unique constraints for deduplication."""
        try:
            with self._get_connection() as conn:
                conn.execute("""CREATE TABLE IF NOT EXISTS results 
                    (id INTEGER PRIMARY KEY, timestamp TEXT, ip TEXT, target TEXT, 
                     family TEXT, port INTEGER, proto TEXT, service TEXT, 
                     version TEXT, banner TEXT, severity TEXT,
                     UNIQUE(ip, target, port))""")
                
                conn.execute("""CREATE TABLE IF NOT EXISTS scan_sessions
                    (id INTEGER PRIMARY KEY, session_id TEXT, ip TEXT, completed_at TEXT,
                     UNIQUE(session_id, ip))""")
                
                conn.execute("""CREATE TABLE IF NOT EXISTS revoked_tokens
                    (token TEXT PRIMARY KEY, revoked_at TEXT)""")
                
                conn.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)")
                conn.execute("INSERT OR IGNORE INTO metadata (key, value) VALUES ('version', '12.0')")
                
                conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON results(ip)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_time ON results(timestamp)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_session ON scan_sessions(session_id, ip)")
        except sqlite3.Error as e:
            logger.error(f"DB Setup Failed: {e}")

    async def _background_writer(self):
        """Processes the queue in batches with crash recovery."""
        queue = self.write_queue
        while self.is_running or not queue.empty():
            batch = []
            try:
                while len(batch) < Config.DB_BATCH_SIZE:
                    try:
                        item = await asyncio.wait_for(queue.get(), timeout=0.5 if not batch else 0.1)
                        batch.append(item)
                    except (asyncio.TimeoutError, asyncio.QueueEmpty): break
                
                if batch:
                    self._execute_batch(batch)
                    for _ in range(len(batch)): queue.task_done()
                        
            except asyncio.CancelledError: break
            except Exception as e:
                logger.error(f"DB Writer Error: {e}")
                await asyncio.sleep(1)

    def _execute_batch(self, batch):
        try:
            with self._get_connection() as conn:
                for item_type, data in batch:
                    if item_type == "result":
                        conn.executemany("""INSERT OR REPLACE INTO results 
                            (timestamp, ip, target, family, port, proto, service, version, banner, severity) 
                            VALUES (?,?,?,?,?,?,?,?,?,?)""", data)
                    elif item_type == "session":
                        conn.execute("INSERT OR IGNORE INTO scan_sessions (session_id, ip, completed_at) VALUES (?,?,?)", data)
        except sqlite3.Error as e:
            logger.error(f"Batch Commit Failed: {e}")

    def save_batch(self, host_info, ports, session_id=None):
        """Enqueue data with backpressure handling."""
        self._ensure_writer_started()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        results_data = []
        if ports:
            for p in ports:
                results_data.append((
                    timestamp, host_info["ip"], host_info["target"], host_info.get("family", "IPv4"),
                    p["port"], p["proto"], p["service"], p.get("version", "N/A"), p["banner"], p["severity"]
                ))
        else:
            results_data.append((
                timestamp, host_info["ip"], host_info["target"], host_info.get("family", "IPv4"),
                None, "NONE", "NONE", "NONE", "NONE", "INFO"
            ))
        
        try:
            self.write_queue.put_nowait(("result", results_data))
            if session_id:
                self.write_queue.put_nowait(("session", (session_id, host_info["ip"], timestamp)))
        except asyncio.QueueFull:
            logger.error("DB Write Queue overflow! Throttling...")

    async def close(self):
        """Strict graceful shutdown: Wait for queue to flush."""
        logger.info("Flushing DB queue...")
        self.is_running = False
        try:
            if self._write_queue:
                await asyncio.wait_for(self._write_queue.join(), timeout=30.0)
        except asyncio.TimeoutError:
            logger.warning("DB flush timed out. Potential data loss.")
            
        if self.writer_task:
            self.writer_task.cancel()
            try: await self.writer_task
            except asyncio.CancelledError: pass

    def cleanup_old_data(self, days=30):
        try:
            since = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
            with self._get_connection() as conn:
                conn.execute("DELETE FROM results WHERE timestamp < ?", (since,))
                conn.execute("DELETE FROM scan_sessions WHERE completed_at < ?", (since,))
                logger.info(f"Cleaned up data older than {days} days.")
        except sqlite3.Error as e:
            logger.error(f"Cleanup failed: {e}")

    def is_already_scanned(self, ip, hours=24):
        try:
            since = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT 1 FROM results WHERE ip = ? AND timestamp > ? LIMIT 1", (ip, since))
                return bool(cursor.fetchone())
        except sqlite3.Error: return False

    def revoke_token(self, token: str):
        try:
            with self._get_connection() as conn:
                conn.execute("INSERT OR IGNORE INTO revoked_tokens (token, revoked_at) VALUES (?,?)", 
                             (token, datetime.now().isoformat()))
        except sqlite3.Error as e:
            logger.error(f"Failed to revoke token: {e}")

    def is_token_revoked(self, token: str) -> bool:
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT 1 FROM revoked_tokens WHERE token = ?", (token,))
                return bool(cursor.fetchone())
        except sqlite3.Error: return False
