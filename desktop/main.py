import os
import sys
import tkinter as tk

# Import the local GUI module (run as: python desktop/main.py)
from gui import ForensicApp

def main():
    root = tk.Tk()
    
    # Initialize the forensic application GUI
    app = ForensicApp(root)
    
    def on_closing():
        # Clean up temporary database copy files to maintain a tidy workspace
        app.clean_temp_files()
        root.destroy()
        
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Start the Tkinter main loop
    root.mainloop()

if __name__ == "__main__":
    main()
