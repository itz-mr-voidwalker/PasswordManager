from auth.SecureLayer import SecureLayer
from auth.auth_logging import setup_logging
from auth.onboarding import Setup
from auth.login import Login

class Directer:
    def __init__(self):
        self.enc = SecureLayer()
        self.logger = setup_logging()
        self.logger.info("App Started")
        self.direct()
        self.logger.info("App Closed")
        self.logger.info("="*50)
        
    def direct(self):
        try:
            if self.enc.chk_if_exists():
                self.logger.info("Found User Data, Opening Login")
                login = Login()
                login.mainloop()
                
            else:
                self.logger.info("Opening First time setup")
                setup = Setup()
                setup.mainloop()
        except Exception as e:
            self.logger.error("Error while directing to authentication")
    
def main():
    Directer()
    
if __name__ == "__main__":
    main()
    