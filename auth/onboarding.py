import tkinter as tk
from tkinter import ttk, messagebox
import re
from auth.login import Login
import time
import random
from auth.email_sender import EmailVerification
from auth.SecureLayer import SecureLayer
from auth.auth_logging import setup_logging

class Setup(tk.Tk):
    """
    A modern dark-themed setup window using Tkinter.

    Contains fields for username, email, password, and a submit button.
    Validates inputs and handles errors gracefully.
    """

    def __init__(self):
        self.logger = setup_logging()
        super().__init__()

        self.title("Onboarding - Setup")
        self.geometry("400x420")
        self.resizable(False, False)
        
        self.enc = SecureLayer()
        
        # Set dark theme colors
        self.colors = {
            "background": "#121212",
            "foreground": "#E0E0E0",
            "entry_bg": "#1E1E1E",
            "entry_fg": "#E0E0E0",
            "button_bg": "#2979FF",
            "button_fg": "#FFFFFF",
            "error_fg": "#FF5252",
            "accent": "#2979FF"
        }

        self.configure(bg=self.colors["background"])

        # Style the ttk widgets
        self.style = ttk.Style(self)
        self._set_dark_style()

        # Initialize UI
        self._create_widgets()

    def _set_dark_style(self):
        """
        Configure ttk style to use dark theme colors.
        """
        # Use 'clam' to enable more styling options in ttk
        self.style.theme_use("clam")

        # Frame and label style
        self.style.configure("TFrame", background=self.colors["background"])
        self.style.configure("TLabel", background=self.colors["background"], foreground=self.colors["foreground"], font=("Segoe UI", 11))
        self.style.configure("TEntry", 
                             fieldbackground=self.colors["entry_bg"],
                             foreground=self.colors["entry_fg"], 
                             bordercolor=self.colors["accent"],
                             borderwidth=2,
                             padding=6,
                             font=("Segoe UI", 11)
                            )
        self.style.map("TEntry",
                       focus=[('active', self.colors["accent"]),
                              ('!focus', self.colors["entry_bg"])],
                       foreground=[('disabled', '#888888')])

        self.style.configure("TButton",
                             background=self.colors["button_bg"],
                             foreground=self.colors["button_fg"],
                             font=("Segoe UI Semibold", 11),
                             padding=8)
        self.style.map("TButton",
                       background=[('active', '#1C54B2'), ('!active', self.colors["button_bg"])])

    def _create_widgets(self):
        """
        Create and place all widgets on the window.
        """
        # Container frame with padding to provide left and right space
        container = ttk.Frame(self, padding=(20, 20, 20, 20))
        container.pack(expand=True, fill=tk.BOTH)

        # Title Label
        title_label = ttk.Label(container, text="Create your Account", font=("Segoe UI Semibold", 20, "bold"))
        title_label.pack(pady=(0, 20))

        # Username
        self.username_var = tk.StringVar()
        username_label = ttk.Label(container, text="Username:")
        username_label.pack(anchor=tk.W, pady=(0, 5), padx=(10,10))
        self.username_entry = ttk.Entry(container, textvariable=self.username_var)
        self.username_entry.pack(fill=tk.X, pady=(0, 15), padx=(10,10))

        # Email
        self.email_var = tk.StringVar()
        email_label = ttk.Label(container, text="Email:")
        email_label.pack(anchor=tk.W, pady=(0, 5), padx=(10,10))
        self.email_entry = ttk.Entry(container, textvariable=self.email_var)
        self.email_entry.pack(fill=tk.X, pady=(0, 15), padx=(10,10))

        # Password
        self.password_var = tk.StringVar()
        password_label = ttk.Label(container, text="Password:")
        password_label.pack(anchor=tk.W, pady=(0, 5), padx=(10,10))
        self.password_entry = ttk.Entry(container, textvariable=self.password_var, show="•")
        self.password_entry.pack(fill=tk.X, pady=(0, 25), padx=(10,10))

        # Submit Button
        submit_button = ttk.Button(container, text="Submit", command=self._submit)
        submit_button.pack(fill=tk.X, padx=(10,10))

    def _submit(self):
        try:
            """
            Handle submit button click: validate input fields and show messages.
            """
            username = self.username_var.get().strip()
            email = self.email_var.get().strip()
            password = self.password_var.get()

            # Validate username
            if not username:
                self._show_error("Username cannot be empty.")
                self.username_entry.focus()
                return

            # Validate email format
            if not self._is_valid_email(email):
                self._show_error("Please enter a valid email address.")
                self.email_entry.focus()
                return

            # Validate password length
            if len(password) < 6:
                self._show_error("Password must be at least 6 characters long.")
                self.password_entry.focus()
                return
            
            if self._is_email_verified(email):                           

            # If all validations pass
                try:
                    if self.enc.encrypt_data(username,email,password):
                        self.logger.info("Setup Completed Successfully")
                        self._show_success(f"Account created successfully!\nUsername: {username}\nEmail: {email}")
                        self.destroy()
                        login = Login()
                        login.mainloop()
    
                    
                    self.logger.error("Encryption Error")
                except Exception as e:
                    self.logger.error(e)


            # Clear fields as fallback mechanism
            self._clear_fields()
        except Exception as e:
            self.logger.error(f"Error While Validating in Onboarding.py {e}")


    def _is_email_verified(self, email):
        
        try:
            generated_code = random.randrange(10000,99999)
            created_at = int(time.time())
            email_sender = EmailVerification()            
            email_sender.send_email('Email Verification - Password Manager', generated_code, email)
            self.logger.info("Email Code Sent !")
        except:
            self.logger.error("Can't Send Email Verification Code")
            return  
        
        verified= False
        sub_window = tk.Toplevel(self)
        sub_window.grab_set()
        sub_window.title("Email Verification")
        sub_window.geometry("300x200")
        sub_window.configure(bg=self.colors["background"])
        
        label = ttk.Label(sub_window, text="Enter the 5-digit code sent to your email:")
        label.pack(pady=10)

        code_entry = ttk.Entry(sub_window)
        code_entry.pack(pady=10)
        
        def _on_submit():
            nonlocal verified
            try:
                entered_code = int(code_entry.get())
                current_time = int(time.time())
                
                if current_time - created_at >600:
                    self._show_error("Code Expired")
                    self.logger.error("Code Expired, Retry")
                if entered_code == generated_code:
                    self.logger.info("Code Verification Successful")
                    verified=True
                    self._show_success("Email Verification Sucess")
                    
                else:
                    self.logger.error("Wrong Code")
                    verified=False
                    self._show_error("Wrong Code!, Retry")
                sub_window.destroy()
                
            except:
                self.logger.error("Can't Validate Code")
                return
            
        submit_btn = ttk.Button(sub_window, text="Verify", command=_on_submit)
        submit_btn.pack(pady=20)     
        self.wait_window(sub_window)
        return verified
    
    
    
    

    def _is_valid_email(self, email):
        EMAIL_REGEX = re.compile(
                r"""(?xi)                                     # Enable verbose and case-insensitive modes
                ^                                             # Start of string
                [a-z0-9!#$%&'*+/=?^_`{|}~-]+                  # Local part
                    (?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*       # Dots in local part
                @                                             # @ symbol
                (?:
                    [a-z0-9]                                  # Domain start
                    (?:[a-z0-9-]{0,61}[a-z0-9])?              # Domain middle
                    \.                                        # Dot before TLD
                )+                                            # Repeatable domain parts
                [a-z]{2,63}                                   # TLD (e.g., com, io, co.uk)
                $                                             # End of string
                """
            )
        return bool(EMAIL_REGEX.match(email))
    
    def _show_error(self, message):
        """
        Show an error message box.

        Args:
            message (str): The message to display.
        """
        messagebox.showerror("Error", message)

    def _show_success(self, message):
        """
        Show an info message box for success.

        Args:
            message (str): The message to display.
        """
        messagebox.showinfo("Success", message)

    def _clear_fields(self):
        """
        Clear all input fields.
        """
        self.username_var.set("")
        self.email_var.set("")
        self.password_var.set("")
        self.username_entry.focus()


