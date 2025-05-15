import tkinter as tk
from tkinter import ttk, messagebox
import re
from auth.SecureLayer import SecureLayer
from app.main import main
from auth.session_control import SessionManager
from auth.auth_logging import setup_logging
from auth.forgot_pass import ForgotPasswordApp

class Login(tk.Tk):
    """
    A modern dark-themed login window using Tkinter.

    Contains fields for username, password, a submit button,
    and a 'Forgot Password?' action.
    Validates inputs and handles errors gracefully.
    """

    def __init__(self):
        super().__init__()
        
        self.enc = SecureLayer()
        self.sm = SessionManager(3600)
        self.logger = setup_logging()
        self.title("Login")
        self.geometry("400x380")
        self.resizable(False, False)
        
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
        self.style.theme_use("clam")

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

        # Style for clickable forgot password label
        self.style.configure("Forgot.TLabel", foreground="#2979FF", background=self.colors["background"], font=("Segoe UI", 10, "underline"))

    def _create_widgets(self):
        """
        Create and place all widgets on the window.
        """
        container = ttk.Frame(self, padding=(20, 20, 20, 20))
        container.pack(expand=True, fill=tk.BOTH)

        title_label = ttk.Label(container, text="Login to your Account", font=("Segoe UI Semibold", 20, "bold"))
        title_label.pack(pady=(0, 25))

        # Username
        self.username_var = tk.StringVar()
        username_label = ttk.Label(container, text="Username:")
        username_label.pack(anchor=tk.W, pady=(0,5), padx=(10,10))
        self.username_entry = ttk.Entry(container, textvariable=self.username_var)
        self.username_entry.pack(fill=tk.X, pady=(0, 15), padx=(10,10))

        # Password
        self.password_var = tk.StringVar()
        password_label = ttk.Label(container, text="Password:")
        password_label.pack(anchor=tk.W, pady=(0,5), padx=(10,10))
        self.password_entry = ttk.Entry(container, textvariable=self.password_var, show="•")
        self.password_entry.pack(fill=tk.X, pady=(0, 10), padx=(10,10))

        # Forgot password clickable label
        self.forgot_password_label = ttk.Label(container, text="Forgot Password?", style="Forgot.TLabel", cursor="hand2")
        self.forgot_password_label.pack(anchor=tk.E, pady=(0, 20), padx=(10,10))
        self.forgot_password_label.bind("<Button-1>", self._forgot_password_clicked)

        # Submit Button
        submit_button = ttk.Button(container, text="Login", command=self._submit)
        submit_button.pack(fill=tk.X, padx=(10,10))

    def _forgot_password_clicked(self, event=None):
        """
        Callback for forgot password click.

        This is a placeholder for the forgot password logic.
        """
        # Display info message or handle the forgot password flow here
       
        _forgot = ForgotPasswordApp()
        _forgot.mainloop()
        
    def _submit(self):
        """
        Handle submit button click: validate inputs and show messages.
        """
        username = self.username_var.get().strip()
        password = self.password_var.get()

        # Validate username is not empty
        if not username:
            self._show_error("Username cannot be empty.")
            self.username_entry.focus()
            return

        # Validate password length (at least 6 characters)
        if len(password) < 6:
            self._show_error("Password must be at least 6 characters long.")
            self.password_entry.focus()
            return
        try:
            if self.enc.validate_user(username, password):
                self._show_success(f"Login successful!\nWelcome, {username}.")
                self.logger.info("Login Successful")                
                session = self.sm.create_session(username)
                self.logger.info("Session Created")
                self.destroy()
                main(session, self.logger)
                return
            else:
                self.logger.error("Invalid Credentials")
                self._show_error("Invalid Credentials")
                
        except Exception as e:
            self.logger.error("Error While Validating User")
            return
            

        # All validations passed
        
        # Clear fields as fallback
        self._clear_fields()

    def _show_error(self, message):
        """
        Show an error message dialog.

        Args:
            message (str): Message string to display.
        """
        messagebox.showerror("Error", message)

    def _show_success(self, message):
        """
        Show a success message dialog.

        Args:
            message (str): Message string to display.
        """
        messagebox.showinfo("Success", message)

    def _clear_fields(self):
        """
        Clear the input fields.
        """
        self.username_var.set("")
        self.password_var.set("")
        self.username_entry.focus()

