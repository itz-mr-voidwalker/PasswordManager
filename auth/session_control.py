# session_control.py
import uuid
import time

class SessionManager:
    sessions = {}  # <--- Class-level variable, shared by all instances

    def __init__(self, timeout=3600):
        self.timeout = timeout

    def create_session(self, username) -> str:
        session_id = str(uuid.uuid4())
        SessionManager.sessions[session_id] = {
            "username": username,
            "created_at": time.time(),
            "expires_at": time.time() + self.timeout
        }
        return session_id

    def is_session_valid(self, session_id) -> bool:
        session = SessionManager.sessions.get(session_id)
        if session and time.time() < session["expires_at"]:
            return True
        else:
            SessionManager.sessions.pop(session_id, None)
            return False

    def get_user(self, session_id):
        if self.is_session_valid(session_id):
            return SessionManager.sessions[session_id]["username"]
        return None

    def destroy_session(self, session_id):
        SessionManager.sessions.pop(session_id, None)
