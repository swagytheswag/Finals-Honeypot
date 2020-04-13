import time
import logging
import Tkinter as tk
import ScrolledText
import re


class TextHandler(logging.Handler):
    # This class allows you to log to a Tkinter Text or ScrolledText widget

    def __init__(self, text):
        # run the regular Handler __init__
        logging.Handler.__init__(self)
        # Store a reference to the Text it will log to
        self.text = text
        self.row_counter = 0

    def emit(self, record):
        msg = self.format(record)

        def append():
            self.text.configure(state='normal')
            self.text.insert(tk.END, msg + '\n')
            self.row_counter += 1
            self.text.tag_add("time", str(self.row_counter)+".0", str(self.row_counter)+".23")
            self.text.tag_config("time", background="black", foreground="green")
            if 'INFO' in msg:
                self.text.tag_add("info", str(self.row_counter) + ".26", str(self.row_counter) + "." + str(26+len('INFO')))
                self.text.tag_config("info", background="green", foreground="black")
            elif 'WARNING' in msg:
                self.text.tag_add("warning", str(self.row_counter) + ".26", str(self.row_counter) + "." + str(26+len('WARNING')))
                self.text.tag_config("warning", background="red", foreground="black")

            self.text.configure(state='disabled')
            # Autoscroll to the bottom
            self.text.yview(tk.END)

        # This is necessary because we can't modify the Text from other threads
        self.text.after(0, append)


class myGUI(tk.Frame):

    # This class defines the graphical user interface

    def __init__(self, parent, *args, **kwargs):
        tk.Frame.__init__(self, parent, *args, **kwargs)
        self.root = parent
        self.build_gui()

    def build_gui(self):
        # Build GUI
        self.root.title('LoggerGui')
        #self.root.option_add('*tearOff', 'FALSE')
        #self.grid(column=0, row=0, sticky='NSWE')

        # Add text widget to display logging info
        st = ScrolledText.ScrolledText(self.root, state='disabled')
        st.configure(font='TkFixedFont')
        st.pack(side='left', fill='both', expand='YES')

        # Create textLogger
        self.text_handler = TextHandler(st)

    def gui_worker(self):
        self.root.mainloop()
        time.sleep(2)

