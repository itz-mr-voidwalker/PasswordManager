import tkinter as tk
from tkinter import ttk, messagebox
import random
import os
import json
import threading
from typing import Tuple
import keyring
import time
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import string

class PasswordManager(tk.Tk):
    """Main application class for the Password Manager."""
    
    def __init__(self, logger):
        """Initialize the Password Manager application."""
        self.logger = logger
        try:
            load_dotenv()
            
            super().__init__()
            self.data_file = os.getenv('PROGRAM_DATA_FILE')
            self.title(os.getenv('PROGRAM_APP_NAME'))
            self.geometry("480x420")
            self.resizable(False, False)
            self.configure(bg="#121212")  # Dark background

            # Data store for passwords (for demo purposes only; no persistence)
            self.setup_cipher()
            self.password_data = self.load_entries()
            
            # Setup UI
            self._setup_widgets()
            
        except Exception as e:
            self.logger.error(e)       

    def load_entries(self)->dict:
        try:
            tmp_dct = {}
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r') as file:
                    for line in file:
                        data = json.loads(line.strip())
                        tmp_dct.update(data)
                    return tmp_dct
            else:
                return tmp_dct
        except Exception as e:
            print(e)

    def _setup_widgets(self):
        
        """Setup the UI widgets for the main application."""
        try:
            # Fonts and colors
            self.font_title = ("Segoe UI", 20, "bold")
            self.font_label = ("Segoe UI", 11)
            self.font_entry = ("Segoe UI", 12)
            self.color_primary = "#BB86FC"
            self.color_bg = "#121212"
            self.color_fg = "#E0E0E0"
            self.color_entry_bg = "#1E1E1E"
            self.color_border = "#BB86FC"
            self.color_select_bg = "#3700B3"
            self.color_select_fg = "#E0E0E0"
            self.color_btn_bg = "#2979FF"
            self.color_btn_hover = "#6200EE"
            self.color_border = "#BB86FC"

            # Title label
            title_label = tk.Label(self, text=os.getenv('PROGRAM_APP_NAME'), font=self.font_title, fg=self.color_primary, bg=self.color_bg)
            title_label.pack(pady=(15, 10))

            # Container frame with padding
            container = tk.Frame(self, bg=self.color_bg)
            container.pack(padx=20, fill="x")

            # Website
            self._create_labeled_entry(container, "Website:", "website").pack(fill="x", pady=5)

            # Username / Email
            self._create_labeled_entry(container, "Username/Email:", "username").pack(fill="x", pady=5)

            # Password frame: entry + generate button
            pass_frame = tk.Frame(container, bg=self.color_bg)
            pass_frame.pack(fill="x", pady=5)

            pass_label = tk.Label(pass_frame, text="Password:", font=self.font_label, fg=self.color_fg, bg=self.color_bg)
            pass_label.pack(anchor="w")

            entry_btn_frame = tk.Frame(pass_frame, bg=self.color_bg)
            entry_btn_frame.pack(fill="x", pady=(2, 0))

            self.password_entry = tk.Entry(entry_btn_frame, font=self.font_entry, bg=self.color_entry_bg,
                                        fg=self.color_fg, insertbackground=self.color_fg,
                                        borderwidth=2, relief="groove")
            self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))

            gen_btn = tk.Button(entry_btn_frame, text="Generate", font=("Segoe UI", 10),
                                bg=self.color_btn_bg, fg="white", activebackground=self.color_btn_hover,
                                command=self.generate_password, cursor="hand2", borderwidth=0, padx=12, pady=6)
            gen_btn.pack(side="right")

            # Horizontal separator
            separator = tk.Frame(container, bg=self.color_border, height=1)
            separator.pack(fill="x", pady=12)

            # Buttons frame: Save and Search
            btn_frame = tk.Frame(container, bg=self.color_bg)
            btn_frame.pack(fill="x")

            save_btn = tk.Button(btn_frame, text="Save Password", font=("Segoe UI", 12, "bold"),
                                bg=self.color_btn_bg, fg="white", activebackground=self.color_btn_hover,
                                command=self.save_password, cursor="hand2", borderwidth=0, padx=15, pady=8)
            save_btn.pack(side="left", expand=True, fill="x", padx=(0, 10))

            search_btn = tk.Button(btn_frame, text="Search Password", font=("Segoe UI", 12, "bold"),
                                bg=self.color_btn_bg, fg="white", activebackground=self.color_btn_hover,
                                command=self.open_search_window, cursor="hand2", borderwidth=0, padx=15, pady=8)
            search_btn.pack(side="left", expand=True, fill="x")

            # Footer label
            footer = tk.Label(self, text="© 2024 Pro Password Manager", font=("Segoe UI", 9),
                            fg="#777777", bg=self.color_bg)
            footer.pack(side="bottom", pady=8)
        except Exception as e:
            self.logger.error(e)

    def _create_labeled_entry(self, parent, text:str, attr_name:str):
        """
        Creates a labeled entry and assigns it as an attribute for easier access.
        
        Args:
            parent (tk.Widget): Parent container.
            text (str): Label text.
            attr_name (str): Attribute name to assign the entry widget.
            
        Returns:
            tk.Frame: The frame containing label and entry.
        """
        frame = tk.Frame(parent, bg=self.color_bg)
        label = tk.Label(frame, text=text, font=self.font_label, fg=self.color_fg, bg=self.color_bg)
        label.pack(anchor="w")

        entry = tk.Entry(frame, font=self.font_entry, bg=self.color_entry_bg,
                         fg=self.color_fg, insertbackground=self.color_fg,
                         borderwidth=2, relief="groove")
        entry.pack(fill="x", pady=(2, 0))

        setattr(self, f"{attr_name}_entry", entry)
        return frame

    def generate_password(self):
        
        """Generate a strong random password and update the password entry."""
        try:
            length = 16
            all_chars = string.ascii_letters + string.digits + string.punctuation
            # Strong password with at least one char type
            while True:
                password = ''.join(random.choice(all_chars) for _ in range(length))
                if (any(c.islower() for c in password)
                    and any(c.isupper() for c in password)
                    and any(c.isdigit() for c in password)
                    and any(c in string.punctuation for c in password)):
                    break
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, password)
            self.clipboard_clear()
            self.clipboard_append(password)
            messagebox.showinfo("Password Generated", "Strong password generated and copied to clipboard!")
            self.logger.info("Password Generated!")
        except Exception as e:
            self.logger.error("Can't Generate Password")
    
    def setup_cipher(self):
        try:
            self.key = keyring.get_password('password_manager', 'admin')
            if self.key is None:
                self.key = Fernet.generate_key()
                keyring.set_password('password_manager', 'admin', self.key.decode())
            self.cipher = Fernet(self.key)
            
        except Exception as e:
            print(f"Exception While Cipher Setup - {e}")
    
    def save_to_file(self)->bool:
        try:
            with open(self.data_file, 'w') as file:
                file.write(json.dumps(self.password_data)+"\n")
                return True
            return False
        except Exception as e:
            self.logger.error(e)
    
    def save_password(self)->None|str:
        """Save the current password entry after validation."""
        try:
            website = self.website_entry.get().strip()
            username = self.username_entry.get().strip()
            password = self.password_entry.get().strip()

            if not website or not username or not password:
                messagebox.showwarning("Input Error", "Please fill in all fields before saving.")
                self.logger.error("Please fill in all fields before saving.")
                return
            
            encrypted_pass = self.cipher.encrypt(password.encode())
            new_entry = {
                'username':username,
                'password':encrypted_pass.decode()
            }
            
            if website not in self.password_data:
                self.password_data[website] = []
                
            for entry in self.password_data[website]:
                if entry["username"] == username:
                    messagebox.showerror("Error",f"⚠️ Username '{username}' already exists under service '{website}'.")
                    self.logger.error(f"⚠️ Username '{username}' already exists under service '{website}'.")
                    return

            self.password_data[website].append(new_entry)
            if self.save_to_file():
                self.clear_entries()
                messagebox.showinfo("Saved", f"Password saved for {website}.")
                self.logger.info(f"Password saved for {website}.")
                
        except Exception as e:
            self.logger.error(e)
        
    def open_search_window(self)->None:
        """Open the search window or bring it to front if already opened."""
        if hasattr(self, "search_window") and self.search_window.winfo_exists():
            self.search_window.lift()
            return
        self.search_window = SearchWindow(self)

    def clear_entries(self):
        """Clear all input fields."""
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        
    
    
        
class SearchWindow(tk.Toplevel):
    """Window for searching, editing, deleting, and copying saved passwords."""

    def __init__(self, parent):
        """Initialize the Search Window."""
        try:
            super().__init__(parent)
            self.parent = parent
            self.title("🔍 Search Passwords")
            self.geometry("600x520")
            self.configure(bg="#121212")
            self.resizable(False, False)

            # Fonts and colors consistent with parent
            self.font_label = ("Segoe UI", 11)
            self.font_entry = ("Segoe UI", 12)
            self.font_tree = ("Segoe UI", 10)
            self.color_bg = "#121212"
            self.color_fg = "#E0E0E0"
            self.color_entry_bg = "#1E1E1E"
            self.color_border = "#BB86FC"
            self.color_select_bg = "#3700B3"
            self.color_select_fg = "#E0E0E0"
            self.color_btn_bg = "#2979FF"
            self.color_btn_hover = "#6200EE"

            self._setup_widgets()
            self.refresh_table()
        except Exception as e:
            self.parent.logger.error(e)

    def _setup_widgets(self):
        """Setup widgets for the search window."""
        try:
            padding_x = 20
            padding_y = 15

            # Search Label and Entry frame
            search_frame = tk.Frame(self, bg=self.color_bg)
            search_frame.pack(fill="x", padx=padding_x, pady=(padding_y, 8))

            search_label = tk.Label(search_frame, text="Search Service:", font=self.font_label, fg=self.color_fg, bg=self.color_bg)
            search_label.pack(anchor="w")

            self.search_var = tk.StringVar()
            self.search_var.trace_add("write", self.on_search_change)

            search_entry = tk.Entry(search_frame, font=self.font_entry, bg=self.color_entry_bg,
                                    fg=self.color_fg, insertbackground=self.color_fg,
                                    borderwidth=2, relief="groove",
                                    textvariable=self.search_var)
            search_entry.pack(fill="x", pady=(6, 0))

            # Treeview frame with scrollbar
            tree_frame = tk.Frame(self, bg=self.color_bg)
            tree_frame.pack(fill="both", expand=True, padx=padding_x, pady=(10, 8))

            columns = ("service", "username", "password")
            self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
            self.tree.pack(side="left", fill="both", expand=True)

            # Scrollbar
            scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
            scrollbar.pack(side="right", fill="y")
            self.tree.configure(yscroll=scrollbar.set)

            # Treeview columns configuration
            self.tree.heading("service", text="Service")
            self.tree.heading("username", text="Username")
            self.tree.heading("password", text="Password")

            self.tree.column("service", width=200, anchor="w")
            self.tree.column("username", width=180, anchor="w")
            self.tree.column("password", width=180, anchor="w")

            # Style Treeview for dark theme
            style = ttk.Style(self)
            style.theme_use('clam')

            style.configure("Treeview",
                            background=self.color_entry_bg,
                            foreground=self.color_fg,
                            fieldbackground=self.color_entry_bg,
                            font=self.font_tree,
                            bordercolor=self.color_border,
                            borderwidth=0,
                            rowheight=28)

            style.map("Treeview",
                    background=[('selected', self.color_select_bg)],
                    foreground=[('selected', self.color_select_fg)])

            style.configure("Treeview.Heading",
                            background=self.color_border,
                            foreground=self.color_fg,
                            font=("Segoe UI", 11, "bold"))

            # Buttons frame for Edit, Delete, and Copy Password
            btn_frame = tk.Frame(self, bg=self.color_bg)
            btn_frame.pack(fill="x", padx=padding_x, pady=(0, padding_y))

            edit_btn = tk.Button(btn_frame, text="Edit Selected", font=("Segoe UI", 11, "bold"),
                                bg=self.color_btn_bg, fg="white", activebackground=self.color_btn_hover,
                                cursor="hand2", borderwidth=0, padx=15, pady=6,
                                command=self.edit_selected)
            edit_btn.pack(side="left", expand=True, fill="x", padx=(0, 10))

            delete_btn = tk.Button(btn_frame, text="Delete Selected", font=("Segoe UI", 11, "bold"),
                                bg=self.color_btn_bg, fg="white", activebackground=self.color_btn_hover,
                                cursor="hand2", borderwidth=0, padx=15, pady=6,
                                command=self.delete_selected)
            delete_btn.pack(side="left", expand=True, fill="x", padx=(0, 10))

            copy_btn = tk.Button(btn_frame, text="Copy Password", font=("Segoe UI", 11, "bold"),
                                bg=self.color_btn_bg, fg="white", activebackground=self.color_btn_hover,
                                cursor="hand2", borderwidth=0, padx=15, pady=6,
                                command=self.copy_password)
            copy_btn.pack(side="left", expand=True, fill="x")
        
        except Exception as e:
            self.parent.logger.error(e)

    def on_search_change(self, *args):
        """Called when search input changes to refresh the table."""
        try:
            self.refresh_table()
        except Exception as e:
            self.parent.logger.error(e)

    def refresh_table(self, *args):
        """
        Refreshes the password table in the search window.
        Filters entries based on the search query and populates the Treeview.
        """
        try:
            query = self.search_var.get().lower()

            # Clear the current contents of the Treeview
            for row in self.tree.get_children():
                self.tree.delete(row)
            

            # Filter and add rows to the Treeview
            for service,entries in self.parent.password_data.items():
                for entry in entries:
                    username = entry['username']
                    hidden_password = "*" * len(entry['password'])
                    
                    if not query or query in service.lower() or query in username.lower():
                        self.tree.insert("",tk.END,values=(service, username, hidden_password))
        except Exception as e:
            self.parent.logger.error(e)
    
    def get_selected_service(self) -> Tuple[str, str, str]:
        """
        Retrieve the currently selected service from the treeview.

        Returns:
            str or None: The selected service name or None if no selection.
        """
        try:
            selected = self.tree.selection()
            if not selected:
                messagebox.showinfo("Selection Required", "Please select a service entry.")
                return None
            item = self.tree.item(selected[0])
            service = item['values'][0]
            username = item['values'][1]
            password =  item['values'][2]
            return service,username,password

        except Exception as e:
            self.parent.logger.error(e)
    
    def edit_selected(self):
        """Open the edit dialog for the selected entry."""
        try:
            service, username, password = self.get_selected_service()
            if not service:
                return        
            

            # Open custom modern edit dialog
            dialog = EditDialog(self, service, username, password)
            self.wait_window(dialog)
            # After dialog closes, check if updates were made
            if dialog.updated_data:           
                uname  = dialog.updated_data['username']
                encryp_password = self.parent.cipher.encrypt(dialog.updated_data['password'].encode()).decode()
                
                entries = self.parent.password_data.get(service, [])
                for entry in entries:
                    if entry['username']==username:
                        entry['username']=uname
                        entry['password']=encryp_password                   
                        if self.parent.save_to_file():
                            messagebox.showinfo("Success", "Edit Successful")
                            self.parent.logger.info(f"Edit Successful for {username}")
                            self.refresh_table()
                            return
                        else:
                            messagebox.showerror("Error while saving edits to file")
                            self.parent.logger.error("Error while saving edits to file")
                            return      
                        
        except Exception as e:
            self.parent.logger.error(e)         
            
    def delete_selected(self):
        """Delete the selected password entry after confirmation."""
        try:
            selected_item = self.tree.selection()
            if not selected_item:
                messagebox.showwarning("No Selection", "Please select an entry to delete.")
                self.parent.logger.error("Please select an entry to delete.")
                return

            service, username, _ = self.get_selected_service()

            confirm = messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete the entry for '{username}' under '{service}'?")
            if not confirm:
                return

            # Remove the entry from the parent's data dictionary
            entries = self.parent.password_data.get(service, [])
            self.parent.password_data[service] = [entry for entry in entries if entry["username"] != username]

            # If no more entries under the service, remove the service key entirely
            if not self.parent.password_data[service]:
                del self.parent.password_data[service]

            # Save to file and refresh UI
            if self.parent.save_to_file():
                self.refresh_table()
                messagebox.showinfo("Deleted", f"The password entry for '{username}' under '{service}' was successfully deleted.")
                self.parent.logger.info(f"The password entry for '{username}' under '{service}' was successfully deleted.")
            else:
                messagebox.showerror("Error", "Failed to save changes to file.")
                self.parent.logger.error("Failed to save changes to file.")
                
        except Exception as e:
            self.parent.logger.error(e)
            
    
    
    def copy_password(self):
        """Copy the password of the selected service to clipboard."""
        try:
            service,username, _ = self.get_selected_service()
            if not service:
                return
            found=False
            for Service, entries in self.parent.password_data.items():
                if Service==service:
                    for entry in entries:
                        if entry['username']==username:
                            try:
                                found=True                            
                                encrypted_password = entry['password']
                                password = self.parent.cipher.decrypt(encrypted_password.encode()).decode()
                                self.clipboard_clear()
                                self.clipboard_append(password)
                                self.update()
                                
                                
                                messagebox.showinfo("Success",'Password Copied to Clipboard, It will last only for 10secs')
                                self.parent.logger.info('Password Copied to Clipboard, It will last only for 10secs')
                                self.timer = threading.Timer(10, self.clipboard_clear)
                                self.timer.start()
                                self.parent.logger.info("Clipboard Cleared")
                                break
                            except Exception as e:
                                self.parent.logger.error(e)    
             
            if not found:
                print("There was an error while parsing the password")
                self.parent.logger.info("There was an error while parsing the password")         

            
            if not password:
                messagebox.showerror("Error", f"No password found for {service}.")
                self.parent.logger.info(f"No password found for {service}.")
                return
        except Exception as e:
            self.parent.logger.error(e)
        
        

class EditDialog(tk.Toplevel):
    """Dialog window to edit username and password for a selected service."""

    def __init__(self, parent, service, username, password):
        """
        Initialize the Edit dialog.

        Args:
            parent (tk.Widget): Parent widget.
            service (str): The service name being edited.
            username (str): Current username/email.
            password (str): Current password.
        """
        super().__init__(parent)
        self.parent = parent
        self.service = service
        self.updated_data = None  # To hold updated username and password on submit

        # Dark theme colors/fonts
        self.color_bg = "#121212"
        self.color_fg = "#E0E0E0"
        self.color_entry_bg = "#1F1B24"
        self.color_btn_bg = "#3700B3"
        self.color_btn_hover = "#6200EE"
        self.color_border = "#BB86FC"
        self.font_label = ("Segoe UI", 11)
        self.font_entry = ("Segoe UI", 12)
        self.font_btn = ("Segoe UI", 11, "bold")

        self.configure(bg=self.color_bg)
        self.title(f"Edit '{service}'")

        self.geometry("400x220")
        self.resizable(True, True)

        self.username_var = tk.StringVar(value=username)
        self.password_var = tk.StringVar(value=password)

        self._setup_widgets()
        self.transient(parent)  # Set to be modal
        self.grab_set()
        self.focus_force()

    def _setup_widgets(self):
        """Setup UI widgets inside the edit dialog."""
        padding_x = 20
        padding_y = 15

        lbl_service = tk.Label(self, text=f"Editing service: {self.service}", font=("Segoe UI", 13, "bold"),
                               fg=self.color_fg, bg=self.color_bg)
        lbl_service.pack(pady=(padding_y, 10))

        # Username
        user_frame = tk.Frame(self, bg=self.color_bg)
        user_frame.pack(fill="x", padx=padding_x, pady=(0, padding_y))

        user_label = tk.Label(user_frame, text="Username/Email:", font=self.font_label,
                              fg=self.color_fg, bg=self.color_bg)
        user_label.pack(anchor="w")

        user_entry = tk.Entry(user_frame, font=self.font_entry, bg=self.color_entry_bg,
                              fg=self.color_fg, insertbackground=self.color_fg,
                              borderwidth=2, relief="groove",
                              textvariable=self.username_var)
        user_entry.pack(fill="x", pady=(4, 0))

        # Password
        pass_frame = tk.Frame(self, bg=self.color_bg)
        pass_frame.pack(fill="x", padx=padding_x, pady=(0, padding_y))

        pass_label = tk.Label(pass_frame, text="Password:", font=self.font_label,
                              fg=self.color_fg, bg=self.color_bg)
        pass_label.pack(anchor="w")

        pass_entry = tk.Entry(pass_frame, font=self.font_entry, bg=self.color_entry_bg,
                              fg=self.color_fg, insertbackground=self.color_fg,
                              borderwidth=2, relief="groove",
                              textvariable=self.password_var,
                              show="*")
        pass_entry.pack(fill="x", pady=(4, 0))

        # Buttons frame
        btn_frame = tk.Frame(self, bg=self.color_bg)
        btn_frame.pack(pady=(10, padding_y))

        submit_btn = tk.Button(btn_frame, text="Submit", font=self.font_btn,
                               bg=self.color_btn_bg, fg="white", activebackground=self.color_btn_hover,
                               cursor="hand2", borderwidth=0, padx=20, pady=8,
                               command=self.on_submit)
        submit_btn.pack(side="left", padx=8)

        cancel_btn = tk.Button(btn_frame, text="Cancel", font=self.font_btn,
                               bg="#555555", fg="white", activebackground="#777777",
                               cursor="hand2", borderwidth=0, padx=20, pady=8,
                               command=self.destroy)
        cancel_btn.pack(side="left", padx=8)

    def on_submit(self):
        """Validate inputs and submit updated data."""
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()

        if not username or not password:
            messagebox.showwarning("Input Error", "Username and password cannot be empty.", parent=self)
            return

        self.updated_data = {"username": username, "password": password}
        self.destroy()


