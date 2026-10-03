"""UI themes."""
import tkinter as tk
from tkinter import ttk

class Theme:
    DEFAULT_FONT = ('Segoe UI', 10)
    MONO_FONT = ('Consolas', 9)
    def __init__(self, root):
        self.root = root
        self.current_theme = "dark"
        self.style = ttk.Style()
        self.setup_themes()
    def setup_themes(self):
        self.themes = {
            "light": {
                "window_bg": "#f1f5f9",
                "primary_bg": "#e2e8f0",
                "secondary_bg": "#ffffff",
                "primary_fg": "#0f172a",
                "secondary_fg": "#475569",
                "accent": "#2563eb",
                "accent_hover": "#1d4ed8",
                "border": "#cbd5e1",
                "input_bg": "#ffffff",
                "input_fg": "#0f172a",
                "button_bg": "#334155",
                "button_fg": "#ffffff",
                "tree_bg": "#ffffff",
                "tree_fg": "#0f172a",
                "tree_selected": "#dbeafe",
                "text_bg": "#ffffff",
                "text_fg": "#0f172a",
                "scrollbar_bg": "#cbd5e1",
                "scrollbar_trough": "#e2e8f0",
                "scrollbar_arrow": "#475569",
                "header_bg": "#f8fafc",
                "header_fg": "#334155",
                "field_focus": "#bfdbfe"
            },
            "dark": {
                "window_bg": "#111111",
                "primary_bg": "#1B1B1E",
                "secondary_bg": "#232326",
                "primary_fg": "#FFFFFF",
                "secondary_fg": "#C2BFBB",
                "accent": "#798086",
                "accent_hover": "#8a9197",
                "border": "#353535",
                "input_bg": "#202023",
                "input_fg": "#FFFFFF",
                "button_bg": "#353535",
                "button_fg": "#FFFFFF",
                "tree_bg": "#1B1B1E",
                "tree_fg": "#FFFFFF",
                "tree_selected": "#4a4f55",
                "text_bg": "#202023",
                "text_fg": "#FFFFFF",
                "scrollbar_bg": "#444444",
                "scrollbar_trough": "#1B1B1E",
                "scrollbar_arrow": "#C2BFBB",
                "header_bg": "#2A2A2D",
                "header_fg": "#FFFFFF",
                "field_focus": "#3f4348"
            }
        }
    def apply_theme(self, theme_name):
        if theme_name not in self.themes:
            return
        self.current_theme = theme_name
        theme = self.themes[theme_name]
        self.style.theme_use('clam')
        self.style.configure('.',
                             background=theme['primary_bg'],
                             foreground=theme['primary_fg'],
                             fieldbackground=theme['input_bg'],
                             selectbackground=theme['accent'],
                             bordercolor=theme['border'],
                             lightcolor=theme['border'],
                             darkcolor=theme['border'],
                             font=self.DEFAULT_FONT)
        self.root.configure(bg=theme['window_bg'])
        self.root.tk_setPalette(
            background=theme['window_bg'],
            foreground=theme['primary_fg'],
            activeBackground=theme['accent'],
            activeForeground=theme['button_fg']
        )
        self.style.configure('TFrame', background=theme['primary_bg'])
        self.style.configure('TLabel',
                             background=theme['primary_bg'],
                             foreground=theme['primary_fg'],
                             font=self.DEFAULT_FONT)
        self.style.configure('TLabelframe',
                             background=theme['secondary_bg'],
                             foreground=theme['primary_fg'],
                             bordercolor=theme['border'],
                             relief='solid')
        self.style.configure('TLabelframe.Label',
                             background=theme['secondary_bg'],
                             foreground=theme['header_fg'],
                             font=('Segoe UI Semibold', 10))
        self.style.configure('TButton',
                             background=theme['button_bg'],
                             foreground=theme['button_fg'],
                             borderwidth=1,
                             relief='flat',
                             focuscolor=theme['accent'],
                             padding=(8, 4),
                             font=('Segoe UI Semibold', 9),
                             wraplength=150)
        self.style.map('TButton',
                       background=[('active', theme['accent_hover']), ('pressed', theme['accent'])],
                       foreground=[('disabled', theme['secondary_fg'])],
                       relief=[('pressed', 'sunken')])
        self.style.configure('TEntry',
                             fieldbackground=theme['input_bg'],
                             foreground=theme['input_fg'],
                             insertcolor=theme['input_fg'],
                             bordercolor=theme['border'],
                             lightcolor=theme['border'],
                             darkcolor=theme['border'],
                             font=self.DEFAULT_FONT)
        self.style.map('TEntry',
                       fieldbackground=[('focus', theme['field_focus'])],
                       foreground=[('disabled', theme['secondary_fg'])])
        self.style.configure('TCombobox',
                             fieldbackground=theme['input_bg'],
                             foreground=theme['input_fg'],
                             background=theme['button_bg'],
                             arrowcolor=theme['secondary_fg'],
                             bordercolor=theme['border'],
                             lightcolor=theme['border'],
                             darkcolor=theme['border'],
                             font=self.DEFAULT_FONT)
        self.style.configure('TCheckbutton',
                             background=theme['primary_bg'],
                             foreground=theme['primary_fg'],
                             focuscolor=theme['accent'])
        self.style.configure('TNotebook',
                             background=theme['secondary_bg'],
                             bordercolor=theme['border'])
        self.style.configure('TNotebook.Tab',
                             background=theme['header_bg'],
                             foreground=theme['secondary_fg'],
                             padding=(12, 6),
                             font=('Segoe UI', 9))
        self.style.map('TNotebook.Tab',
                       background=[('selected', theme['primary_bg']), ('active', theme['secondary_bg'])],
                       foreground=[('selected', theme['primary_fg']), ('active', theme['primary_fg'])])
        self.style.configure('Treeview',
                             background=theme['tree_bg'],
                             foreground=theme['tree_fg'],
                             fieldbackground=theme['tree_bg'],
                             bordercolor=theme['border'],
                             rowheight=22,
                             font=self.DEFAULT_FONT)
        self.style.configure('Treeview.Heading',
                             background=theme['header_bg'],
                             foreground=theme['header_fg'],
                             relief='flat',
                             font=('Segoe UI Semibold', 9))
        self.style.map('Treeview',
                       background=[('selected', theme['tree_selected'])],
                       foreground=[('selected', theme['primary_fg'])])
        self.style.map('Treeview.Heading',
                       background=[('active', theme['secondary_bg'])])
        self.style.configure('TScrollbar',
                             background=theme['scrollbar_bg'],
                             troughcolor=theme['scrollbar_trough'],
                             arrowcolor=theme['scrollbar_arrow'])
        self.apply_to_widgets(self.root, theme)
    def apply_to_widgets(self, widget, theme):
        widget_stack = [widget]
        while widget_stack:
            current = widget_stack.pop()
            try:
                widget_type = current.winfo_class()
                if widget_type in ('Frame', 'Labelframe', 'LabelFrame'):
                    current.config(bg=theme['primary_bg'], highlightbackground=theme['border'])
                elif widget_type == 'Label':
                    current.config(bg=theme['primary_bg'], fg=theme['primary_fg'], font=self.DEFAULT_FONT)
                elif widget_type == 'Button':
                    current.config(bg=theme['button_bg'], fg=theme['button_fg'],
                                   activebackground=theme['accent_hover'], activeforeground=theme['button_fg'],
                                   font=('Segoe UI Semibold', 9), padx=8, pady=3, wraplength=150,
                                   relief='flat', bd=1)
                elif widget_type == 'Entry':
                    current.config(bg=theme['input_bg'], fg=theme['input_fg'],
                                   insertbackground=theme['input_fg'], font=self.DEFAULT_FONT,
                                   relief='flat', highlightthickness=1,
                                   highlightbackground=theme['border'], highlightcolor=theme['accent'])
                elif widget_type == 'Text':
                    current.config(bg=theme['text_bg'], fg=theme['text_fg'],
                                   insertbackground=theme['text_fg'], selectbackground=theme['accent'],
                                   selectforeground=theme['button_fg'], font=self.MONO_FONT,
                                   relief='flat', highlightthickness=1,
                                   highlightbackground=theme['border'], highlightcolor=theme['accent'])
                elif widget_type == 'Scrollbar':
                    current.config(bg=theme['scrollbar_bg'], troughcolor=theme['scrollbar_trough'],
                                   activebackground=theme['scrollbar_bg'])
                elif widget_type == 'Listbox':
                    current.config(bg=theme['input_bg'], fg=theme['input_fg'],
                                   selectbackground=theme['accent'], selectforeground=theme['button_fg'],
                                   font=self.DEFAULT_FONT)
                elif widget_type == 'Canvas':
                    current.config(bg=theme['primary_bg'], highlightbackground=theme['border'])
            except tk.TclError:
                pass
            widget_stack.extend(current.winfo_children())
