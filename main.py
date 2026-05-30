import os
import sys
import tkinter as tk

# Ensure the root package is in the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from browser_forensics.gui import ForensicApp

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
