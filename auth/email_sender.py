import smtplib
from auth.config import get_env_var as load_env
from email.message import EmailMessage
from auth.auth_logging import setup_logging

class EmailVerification:
    def __init__(self):
        self.logger = setup_logging()
        """
        Initializes the EmailVerification class by securely loading email
        credentials (sender email and app password) from environment variables.
        """
        try:
            self.sender_email = load_env("SENDER_EMAIL")
            self.app_password = load_env("EMAIL_SECRET_KEY")
            self.smtp_address = load_env("SMTP_ADDR")
            self.smtp_port = int(load_env("SMTP_PORT"))

            if not all([self.sender_email, self.app_password, self.smtp_address, self.smtp_port]):
                raise ValueError("One or more environment variables are missing or invalid.")
            
        except Exception as e:
            self.logger.error(f"Error initializing EmailVerification class: {e}")
            raise

    def send_email(self, subject, code:int, to_email:str) -> bool:
        """
        Sends an email verification message with a code to the specified email address.

        Args:
            subject (str): The subject of the email.
            code (int): The verification code to be included in the email body.
            to_email (str): The recipient's email address.

        Returns:
            bool: True if the email was sent successfully, False otherwise.
        """
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = self.sender_email
        msg['To'] = to_email

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Email Verification</title>
            <style>
                body {{
                    font-family: 'Segoe UI', sans-serif;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    background-color: #ffffff;
                    max-width: 500px;
                    margin: 40px auto;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.1);
                }}
                .code {{
                    font-size: 24px;
                    font-weight: bold;
                    background-color: #f0f0f0;
                    padding: 10px 20px;
                    border-radius: 6px;
                    display: inline-block;
                    letter-spacing: 3px;
                    margin: 20px 0;
                }}
                .footer {{
                    margin-top: 30px;
                    font-size: 12px;
                    color: #999;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h2>Email Verification</h2>
                <p>Hello,</p>
                <p>Use the following code to verify your email address:</p>
                <div class="code">{code}</div>
                <p>This code will expire in 10 minutes. If you did not request this, please ignore this message.</p>
                <div class="footer">
                    &copy; 2025 YourApp Inc. All rights reserved.
                </div>
            </div>
        </body>
        </html>
        """

        msg.set_content("Use an HTML-compatible email client to view this message.")
        msg.add_alternative(html_body, subtype='html')

        try:
            with smtplib.SMTP_SSL(self.smtp_address, self.smtp_port) as smtp:
                smtp.login(self.sender_email, self.app_password)
                smtp.send_message(msg)
            self.logger.info("Email Code Sent")
            return True
        except smtplib.SMTPException as e:
            self.logger.error(f"SMTP error occurred: {e}")
        except Exception as e:
            self.logger.error(f"An error occurred while sending email: {e}")
        
        return False


# Example usage (This would be part of your application code):
# Replace these with secure retrieval in real apps
# Avoid putting passwords in source code directly!
# email_verification = EmailVerification()
# email_verification.send_email("Email Verification", 12345, "user@example.com")
