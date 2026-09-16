import sqlite3
import json
from typing import Dict, Any, List

DB_PATH = "wiwp.db"

def dict_factory(cursor, row):
    """Helper to return SQLite rows as dictionaries."""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def init_db() -> None:
    """
    Initializes the SQLite database and performs a lightweight migration 
    to add ChatOps tracking columns if they don't exist.
    """
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE,
                sender TEXT,
                subject TEXT,
                body_preview TEXT,
                defanged_urls TEXT,
                attachment_hashes TEXT,
                vt_results TEXT,
                analysis TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Migration: Add ChatOps tracking columns safely
        cursor.execute("PRAGMA table_info(submissions)")
        existing_columns = [col[1] for col in cursor.fetchall()]
        
        if "action_taken" not in existing_columns:
            cursor.execute("ALTER TABLE submissions ADD COLUMN action_taken TEXT")
        if "actioned_by" not in existing_columns:
            cursor.execute("ALTER TABLE submissions ADD COLUMN actioned_by TEXT")
            
        conn.commit()

def insert_submission(data: Dict[str, Any]) -> int:
    """Inserts a parsed and enriched email record into the database."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR IGNORE INTO submissions 
            (message_id, sender, subject, body_preview, defanged_urls, attachment_hashes, vt_results)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            data.get("message_id", "unknown"),
            data.get("sender", "unknown"),
            data.get("subject", "No Subject"),
            data.get("body_preview", ""),
            json.dumps(data.get("defanged_urls", [])),
            json.dumps(data.get("attachment_hashes", [])),
            json.dumps(data.get("vt_results", {}))
        ))
        conn.commit()
        return cursor.lastrowid

def get_all_pending_submissions() -> List[Dict[str, Any]]:
    """Fetches ALL pending submissions for batch AI triage."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = dict_factory
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM submissions WHERE status = 'pending' ORDER BY created_at ASC")
        rows = cursor.fetchall()
        
        for row in rows:
            row['defanged_urls'] = json.loads(row['defanged_urls']) if row['defanged_urls'] else []
            row['attachment_hashes'] = json.loads(row['attachment_hashes']) if row['attachment_hashes'] else []
            row['vt_results'] = json.loads(row['vt_results']) if row['vt_results'] else {}
            
        return rows

def update_submission_analysis(submission_id: int, analysis: Dict[str, Any]) -> None:
    """Saves the Groq LLM analysis and marks the submission as analyzed."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE submissions SET analysis = ?, status = 'analyzed' WHERE id = ?", 
                       (json.dumps(analysis), submission_id))
        conn.commit()

def get_analyzed_submissions() -> List[Dict[str, Any]]:
    """Fetches all submissions that have been analyzed by Groq but not yet posted to Discord."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = dict_factory
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM submissions WHERE status = 'analyzed' ORDER BY created_at ASC")
        rows = cursor.fetchall()
        for row in rows:
            row['analysis'] = json.loads(row['analysis']) if row['analysis'] else {}
        return rows

def mark_submission_posted(submission_id: int) -> None:
    """Marks a submission as posted to Discord, awaiting human action."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE submissions SET status = 'pending_action' WHERE id = ?", (submission_id,))
        conn.commit()

def resolve_submission(submission_id: int, action: str, user: str) -> None:
    """Closes the loop: records the human action taken and marks the ticket resolved."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE submissions 
            SET status = 'resolved', action_taken = ?, actioned_by = ?
            WHERE id = ?
        """, (action, user, submission_id))
        conn.commit()
