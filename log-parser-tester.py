#!/usr/bin/env python3

import re
import tkinter as tk
from tkinter import scrolledtext, filedialog
import tkinter.font as tkFont

from slugify import slugify
from tklinenums import TkLineNumbers


class LogParserTester:
    def __init__(self, root):
        root.title('Log Parser Tester')

        default_font = tkFont.nametofont("TkDefaultFont")
        default_font.configure(size=11)
        root.option_add("*Font", default_font)

        # List to store regex matches
        self.regex_matches = []

        # PanedWindow - container for log, regex results and naming
        self.panedwindow = tk.PanedWindow(root, orient=tk.HORIZONTAL)

        # Text box to input regex
        self.regex_box = scrolledtext.ScrolledText(root, width=72, undo=True)
        self.regex_box.pack(side=tk.TOP, pady=10)

        # Text box to display log file
        self.log_area = scrolledtext.ScrolledText(self.panedwindow, wrap=tk.WORD, width=72, height=72)
        self.panedwindow.add(self.log_area)

        # Search result display
        self.search_result_area = tk.Listbox(self.panedwindow, width=72, height=72)
        self.panedwindow.add(self.search_result_area)
        self.search_result_area.bind('<<ListboxSelect>>', self.view_current_match)

        # Display proposed name
        self.test_name_area = tk.Listbox(self.panedwindow, width=72, height=72)
        self.panedwindow.add(self.test_name_area)

        # Button for applying the regexes
        self.apply_regex_button = tk.Button(root, text='Apply regexes', command=self.apply_regexes)
        self.apply_regex_button.pack(side=tk.TOP, pady=10)

        # Button to open the log file
        self.open_file_button = tk.Button(root, text='Open log file', command=self.open_file)
        self.open_file_button.pack(side=tk.TOP, pady=10)

        # Line numbers for log file
        self.line_numbers = TkLineNumbers(self.panedwindow, self.log_area, justify="center")
        self.panedwindow.add(self.line_numbers, before=self.log_area)

        # Put the panedwindow together
        self.panedwindow.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    def open_file(self):
        file = filedialog.askopenfile(mode='r', filetypes=[('Log files', '*.log')])
        if file is not None:
            content = file.read()
            self.log_area.delete(1.0, tk.END)
            self.log_area.insert(tk.INSERT, content)

    def apply_regexes(self):
        # Remove old highlights
        self.log_area.tag_remove('highlight', '1.0', tk.END)
        # Remove the search result entries
        self.search_result_area.delete(0, tk.END)
        # Empty matches list
        self.regex_matches.clear()
        # Empty the test name list
        self.test_name_area.delete(0, tk.END)

        # Dict to regex for test names
        names_lookup = dict()
        # Regex patterns list
        patterns = []

        # If the regex box is empty, don't search
        if self.regex_box.get('1.0', tk.END).strip() == "":
            return

        # Go through each regex entry in the regex box and add it to the
        # patterns list and add the name lookup info if it's available
        for entry in self.regex_box.get('1.0', tk.END).rstrip().split('\n'):
            # Name regex can be optionally added after comma
            split_entry = entry.split(",")
            pattern = split_entry[0].strip()
            # If there is a name regex - add a lookup entry
            if len(split_entry) > 1:
                name = split_entry[1].strip()
                names_lookup[pattern] = name

            patterns.append(pattern)

        # Read the log text from the log text box
        log_text = self.log_area.get('1.0', tk.END)

        # Search for each regex pattern in the log
        for pattern in patterns:
            try:
                compiled_pattern = re.compile(pattern, re.S | re.M)
                matches = list(re.finditer(compiled_pattern, log_text))
                for match in matches:
                    start = match.start()
                    end = match.end()
                    start_index = self.log_area.index(f'1.0+{start}c')
                    end_index = self.log_area.index(f'1.0+{end}c')
                    line_number = int(self.log_area.index(start_index).split('.')[0])
                    self.log_area.tag_add('highlight', start_index, end_index)
                    self.log_area.tag_config('highlight', background='yellow')

                    # Add the regex search result to the list
                    self.search_result_area.insert(tk.END, f"Pattern: {pattern}, Line {line_number}: {match.group()}")
                    # Add the regex match start/end indexes to the regex match
                    # list
                    self.regex_matches.append((start_index, end_index))

                    # If there is a name regex for the pattern then use this
                    # before generating the name
                    if pattern in names_lookup:
                        compiled_name_pattern = re.compile(names_lookup[pattern], re.S | re.M)
                        extracted_name = compiled_name_pattern.findall(match.group())
                        name = self.slugify(extracted_name[0])
                    else:
                        name = self.slugify(match.group())

                    # Add the test name to the test name list
                    self.test_name_area.insert(tk.END, name)

            except re.error as e:
                self.search_result_area.insert(tk.END, f"Invalid regex pattern: {pattern} - {e}")

    def view_current_match(self, event):
        # Scrolls to the selected regex match and highlights it orange
        selection = event.widget.curselection()
        if selection:
            regex_index = selection[0]
            log_start_index, log_end_index = self.regex_matches[regex_index]
            self.log_area.see(log_start_index)
            self.log_area.tag_remove('current_highlight', '1.0', tk.END)
            self.log_area.tag_add('current_highlight', log_start_index, log_end_index)
            self.log_area.tag_config('current_highlight', background='orange')

    def slugify(self, text):
        # Remove numbers and timestamps then slugify
        without_numbers = re.sub(r'(0x[a-f0-9]+|[<\[][0-9a-f]+?[>\]]|\d+)', '', text)
        without_time = re.sub(r'^\[[^\]]+\]', '', without_numbers)
        return slugify(without_time)


if __name__ == "__main__":
    root = tk.Tk()
    gui = LogParserTester(root)
    root.mainloop()
