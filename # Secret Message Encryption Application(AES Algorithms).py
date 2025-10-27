# Secret Message Encryption Application
# Now using AES-based Fernet encryption (from cryptography library)
# By Kyaw Zin Thant (Refined with AES)

from tkinter import *
from tkinter import messagebox
import base64
import hashlib
import binascii 
from cryptography.fernet import Fernet, InvalidToken
import os 

# Define the default secret key
SECRET_PASSWORD = "Root@dm!n"

# --- Helper Function for Key Derivation ---

def derive_key(password):
    """
    Derives a 32-byte URL-safe Base64 encoded key from the text password 
    using SHA256 hashing. This is necessary for Fernet encryption.
    """
    # Hash the password using SHA256 to ensure a consistent 32-byte length
    key_hash = hashlib.sha256(password.encode()).digest()
    # Fernet requires the key to be URL-safe Base64 encoded
    return base64.urlsafe_b64encode(key_hash)


# --- Core Logic Functions ---

def decrypt():
    """Decrypts a Fernet-encrypted message after password verification."""
    password = code.get()
    
    # 1. Check for password presence
    if not password:
        messagebox.showerror("Authentication", "Input Password is required.")
        return

    # 2. Check for correct password
    if password == SECRET_PASSWORD:
        
        try:
            encrypted_message_str = text1.get(1.0, END).strip() 
            
            if not encrypted_message_str:
                messagebox.showerror("Decryption Error", "Please enter a message to decrypt.")
                return

            # Derive key and initialize Fernet
            key = derive_key(password)
            f = Fernet(key)

            # Decrypt the message
            # Fernet strings must be bytes, so we encode the input string
            original_message_bytes = f.decrypt(encrypted_message_str.encode())
            decrypt_message = original_message_bytes.decode()

            # Display result in a new window (Toplevel)
            screen2 = Toplevel(screen)
            screen2.title("Decryption Result (AES/Fernet)")
            screen2.geometry("400x200")
            screen2.configure(bg="#00bd56")
            
            Label(screen2, text="DECRYPTED MESSAGE", font=("arial", 12, "bold"), fg="white", bg="#00bd56").place(x=10, y=0)
            text2 = Text(screen2, font="arial 10", bg="white", relief=GROOVE, wrap=WORD, bd=0)
            text2.place(x=10, y=40, width=380, height=150)
            
            text2.insert(END, decrypt_message)
        
        except InvalidToken:
            # This is the specific error for wrong key or corrupted message
            messagebox.showerror("Decryption Error", "Invalid Key or Corrupted Message. Cannot decrypt.")
        except binascii.Error:
             messagebox.showerror("Decryption Error", "Invalid input format.")
        except Exception as e:
            # Catching generic exceptions (e.g., if Fernet failed to initialize)
            messagebox.showerror("Decryption Error", f"An unexpected error occurred during decryption: {e}")

    else:
        # Invalid password
        messagebox.showerror("Authentication", "Invalid Password")

    
def encrypt():
    """Encrypts a message using Fernet (AES-based) after password verification."""
    password = code.get()
    
    # 1. Check for password presence
    if not password:
        messagebox.showerror("Authentication", "Input Password is required.")
        return
        
    # 2. Check for correct password
    if password == SECRET_PASSWORD:
        screen1=Toplevel(screen)
        screen1.title("Encryption Result (AES/Fernet)")
        screen1.geometry("400x200")
        screen1.configure(bg="#ed3833")
        
        message=text1.get(1.0,END).strip()
        
        if not message:
            messagebox.showerror("Encryption Error", "Please enter a message to encrypt.")
            screen1.destroy()
            return

        try:
            # Derive key and initialize Fernet
            key = derive_key(password)
            f = Fernet(key)

            # Encrypt the message
            encrypted_message_bytes = f.encrypt(message.encode())
            encrypt_message = encrypted_message_bytes.decode() 
            
            # Display result in a new window (Toplevel)
            Label(screen1,text="ENCRYPTED MESSAGE (AES-256)",font=("arial", 12, "bold"),fg="white",bg="#ed3833").place(x=10,y=0)
            text2=Text(screen1,font="arial 10", bg="white",relief=GROOVE,wrap=WORD,bd=0)
            text2.place(x=10,y=40,width=380,height=150)
            
            text2.insert(END,encrypt_message)

        except Exception as e:
             messagebox.showerror("Encryption Error", f"An unexpected error occurred during encryption: {e}")

        
    else:
        # Invalid password
        messagebox.showerror("Authentication", "Invalid Password")


def main_screen():
    """Sets up the main Tkinter window and UI elements."""
    global screen
    global code
    global text1
    
    screen=Tk()
    screen.geometry("375x398")
    screen.resizable(False, False) # Prevent resizing for clean layout
     
    screen.title("Msg Encryption App By Kyaw Zin Thant (Secure)")
    
    def reset():
        """Clears the password and text input fields."""
        code.set("")
        text1.delete(1.0,END)
        

    # Input Text Area
    Label(text="Enter Text for encryption and decryption",fg="black",font=("calibri",13)).place(x=10,y=10)
    text1=Text(font="arial 12",bg="white",relief=GROOVE,wrap=WORD,bd=0)
    text1.place(x=10,y=50,width=355,height=100)
    
    # Password Input - Updated Label to reflect stronger security
    Label(text="Enter SECRET KEY for AES encryption",fg="black", font=("calibri",13)).place(x=10,y=170)
    
    code=StringVar()
    Entry(textvariable=code,width=19,bd=0,font=("arial",25),show="*").place(x=10,y=200)
    
    # Buttons
    Button(text="ENCRYPT (AES)",height="2",width=23,bg="#ed3833",fg="white",bd=0,command=encrypt).place(x=10,y=250)
    Button(text="DECRYPT (AES)",height="2",width=23,bg="#00bd56",fg="white",bd=0,command=decrypt).place(x=200,y=250)
    Button(text="RESET",height="2",width=50,bg="#1089ff",fg="white",bd=0,command=reset).place(x=10,y=300)

    screen.mainloop()
    
# Start the application
if __name__ == "__main__":
    main_screen()