import tkinter as tk
from tkinter import messagebox, ttk
from tkinter import font as tkfont
from auth.auth_logging import setup_logging
from auth.email_sender import EmailVerification
from auth.SecureLayer import SecureLayer
import time
import random


class ForgotPasswordApp(tk.Tk):
    """
    A GUI-based password reset interface for a secure password manager.
    This application allows users to reset their password after verifying their email.

    Features:
    - Dark-themed UI for modern aesthetics.
    - Password and confirmation input fields with validation.
    - Email-based OTP verification before password update.
    - Secure encryption and logging mechanisms.
    """

    def __init__(self):
        """
        Initialize the Forgot Password window, UI components, fonts, and logging.
        """
        super().__init__()

        # Secure components
        self.enc = SecureLayer()
        self.logger = setup_logging()

        # Window configuration
        self.title("Forgot Password")
        self.geometry("400x350")
        self.configure(bg="#121212")
        self.resizable(False, False)

        # Fonts
        self.title_font = tkfont.Font(family="Segoe UI", size=18, weight="bold")
        self.label_font = tkfont.Font(family="Segoe UI", size=11)
        self.entry_font = tkfont.Font(family="Segoe UI", size=11)

        # Main container
        container = tk.Frame(self, bg="#1e1e1e")
        container.place(relx=0.5, rely=0.5, anchor="center", width=360, height=300)

        # Title label
        tk.Label(container, text="Forgot Password", bg="#1e1e1e", fg="#ffffff", font=self.title_font).pack(pady=(20, 15))

        # New password entry
        tk.Label(container, text="New Password", bg="#1e1e1e", fg="#dddddd", font=self.label_font, anchor="w").pack(fill='x', padx=30)
        self.new_password_entry = tk.Entry(container, font=self.entry_font, bg="#2c2c2c", fg="#e0e0e0", insertbackground="#e0e0e0",
                                           show="*", bd=0, relief="flat", highlightthickness=2,
                                           highlightcolor="#bb86fc", highlightbackground="#2c2c2c")
        self.new_password_entry.pack(fill='x', padx=30, pady=(0, 15), ipady=6)

        # Confirm password entry
        tk.Label(container, text="Confirm Password", bg="#1e1e1e", fg="#dddddd", font=self.label_font, anchor="w").pack(fill='x', padx=30)
        self.confirm_password_entry = tk.Entry(container, font=self.entry_font, bg="#2c2c2c", fg="#e0e0e0", insertbackground="#e0e0e0",
                                               show="*", bd=0, relief="flat", highlightthickness=2,
                                               highlightcolor="#bb86fc", highlightbackground="#2c2c2c")
        self.confirm_password_entry.pack(fill='x', padx=30, pady=(0, 20), ipady=6)

        # Button group
        buttons_frame = tk.Frame(container, bg="#1e1e1e")
        buttons_frame.pack(fill='x', padx=30)

        # Reset button
        tk.Button(buttons_frame, text="Reset Password", command=self.reset_password,
                  bg="#bb86fc", fg="#121212", font=self.label_font, activebackground="#9b55f9",
                  activeforeground="#121212", relief="flat", bd=0, cursor="hand2").pack(side="left", fill="x", expand=True, pady=(0, 10), ipady=6)

        # Cancel button
        tk.Button(buttons_frame, text="Cancel", command=self.destroy,
                  bg="#2c2c2c", fg="#bbbbbb", font=self.label_font, activebackground="#3a3a3a",
                  activeforeground="#bbbbbb", relief="flat", bd=0, cursor="hand2").pack(side="left", fill="x", expand=True, padx=(10, 0), pady=(0, 10), ipady=6)

        # Bind Enter key to trigger password reset
        self.bind('<Return>', lambda event: self.reset_password())

    def reset_password(self):
        """
        Handle the password reset process including validation,
        email verification, and secure update.
        """
        try:
            new_pwd = self.new_password_entry.get()
            confirm_pwd = self.confirm_password_entry.get()

            # Validate empty input
            if not new_pwd:
                messagebox.showwarning("Input Error", "Please enter a new password.")
                return

            # Validate confirmation match
            if new_pwd != confirm_pwd:
                messagebox.showerror("Password Mismatch", "New Password and Confirm Password do not match.")
                return

            # Decrypt user data to retrieve username and email
            try:
                user = self.enc.decrypt_data()
                username, email = user[0], user[1]
            except Exception as decrypt_err:
                messagebox.showerror("Decryption Error", "Failed to retrieve user details.")
                self.logger.exception("User decryption failed: %s", decrypt_err)
                return

            # Verify email before password reset
            if self._is_email_verified(email):
                if self.enc.encrypt_data(username, email, new_pwd):
                    messagebox.showinfo("Success", f"Password has been reset successfully.")
                    self.logger.info("Password reset successful for user.")
                    self.destroy()
                else:
                    self.logger.error("Password encryption or storage failed.")
                    messagebox.showerror("Encryption Error", "Failed to save new password.")
            else:
                messagebox.showerror("Verification Failed", "Email verification failed or cancelled.")
                self.logger.error("Email verification failed or invalid.")
        except Exception as e:
            self.logger.exception("Unhandled error during password reset: %s", e)
            messagebox.showerror("Unexpected Error", "Something went wrong during the reset process.")

    def _is_email_verified(self, email: str) -> bool:
        """
        Internal method to verify the user's email using a one-time code.
        
        Args:
            email (str): Email address to which the verification code is sent.

        Returns:
            bool: True if verification is successful, False otherwise.
        """
        try:
            generated_code = random.randint(10000, 99999)
            created_at = int(time.time())
            email_sender = EmailVerification()
            email_sender.send_email('Email Verification - Password Manager', generated_code, email)
            self.logger.info(f"Verification code sent to {email}")
        except Exception as e:
            self.logger.exception("Failed to send verification email: %s", e)
            return False

        verified = False

        # Toplevel window for OTP input
        sub_window = tk.Toplevel(self)
        sub_window.grab_set()
        sub_window.title("Email Verification")
        sub_window.geometry("300x200")
        sub_window.configure(bg="#121212")

        tk.Label(sub_window, bg="#121212", fg="#ffffff", text="Enter the 5-digit code sent to your email:").pack(pady=10)
        code_entry = tk.Entry(sub_window, bg="#1e1e1e", fg="#ffffff")
        code_entry.pack(pady=10)

        def _on_submit():
            nonlocal verified
            try:
                entered_code = int(code_entry.get())
                if int(time.time()) - created_at > 600:
                    messagebox.showerror("Code Expired", "Verification code has expired.")
                    self.logger.warning("Verification code expired.")
                elif entered_code == generated_code:
                    verified = True
                    messagebox.showinfo("Success", "Email verification successful.")
                    self.logger.info("Email verified successfully.")
                else:
                    verified = False
                    messagebox.showerror("Invalid Code", "Incorrect verification code.")
                    self.logger.warning("Incorrect verification code entered.")
                sub_window.destroy()
            except ValueError:
                self.logger.warning("Non-integer input for verification code.")
                messagebox.showerror("Invalid Input", "Code must be a 5-digit number.")
            except Exception as e:
                self.logger.exception("Unhandled error during verification: %s", e)
                messagebox.showerror("Error", "Unexpected error occurred during verification.")

        ttk.Button(sub_window, text="Verify", command=_on_submit).pack(pady=20)

        # Wait for the verification window to close before returning status
        self.wait_window(sub_window)
        return verified
