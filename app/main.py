from auth.session_control import SessionManager
from app.app import PasswordManager

class App():
    def __init__(self,session_id, logger):
        
        self.logger = logger
        self.sm = SessionManager()
        self.session_id = session_id
        self.app =PasswordManager(self.logger)
        self.app.mainloop()
        

def main(session_id, logger):
    logging = logger
    sm = SessionManager()
    try:
        if sm.is_session_valid(session_id):            
            obj =App(session_id, logging)
            logging.info("Session Found")
            
        else:
            logging.error("Session is not valid")
    except Exception as e:
        logging.error(e)
    