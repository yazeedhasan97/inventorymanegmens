# PyQt6, support CSS [Cascading Style Sheet]  for design
PROJECTS_LIST_WIDGET_STYLESHEET = """
    QListWidget {
        background: palette(window);
        border: none;
        color: black;
        align-items: center;
        align: center;
        padding: 3px;
    }
    QListWidget::item {
        border-style: solid;
        border-width: 1px;
        border-color: #87CEFA;
        border-radius: 5px;
        margin-right: 3px;
        color: black;
        align-items: center;
        align: center;
        padding: 3px;
    }
    QListWidget::item:hover {
        border-color: #87CEFA;
    }
"""

TASKS_LIST_WIDGET_STYLESHEET = """
    QListWidget {
        border-style: solid;
        border-width: 1px;
        color: black;
        border-radius: 5px;
        align-items: center;
        align: center;
        padding: 3px;
    }
    QListWidget::item {
        border-radius: 5px;
        margin: 3px;
        color: black;
        border-style: dotted;
        align-items: center;
        align: center;
        padding: 3px;
    }
    QListWidget::item:hover {
        border-style: dotted;
    }
"""

GENERAL_QPushButton_STYLESHEET = """
    QPushButton { 
        border-radius: 5px;
        border-style: solid;
        border-width: 1px;
        border-color: black;
        align-items: center;
        align: center;
        padding: 10px;
    }
    QPushButton:hover { 
        border-color: green;
    }
"""

GENERAL_QLabel_STYLESHEET = """
    QLabel { 
        align-items: left;
        align: left;
        padding: 4px;
        margin:3px;
        font-size: 14px;
        font-family: Arial, Helvetica, sans-serif;
        display: block;
    }
"""

SMALLER_QLabel_STYLESHEET = """
    QLabel, QCheckBox { 
        align-items: right;
        align: right;
        padding: 3px;
        margin: 4px;
        font-size: 11px;
        font-family: Arial, Helvetica, sans-serif;
        display: block;
    }
"""

BIGGER_QLabel_STYLESHEET = """
    QLabel, QCheckBox { 
        align-items: left;
        align: left;
        padding: 4px;
        font-size: 16px;
        font-weight: bold;
        font-family:  sans-serif;
        display: block;
    }
"""

GENERAL_QLineEdit_STYLESHEET = """
    QLineEdit { 
        align-items: left;
        align: left;
        padding: 3px;
        border-radius: 5px;
        box-shadow: 3px 3px 5px;
        font-size: 14px;
        font-weight: 200;
        width: 150px;
    }
"""

FLOATING_BAR_STYLESHEET = """
    QFrame {
        background: rgba(0, 0, 0, 0.3);
        border: 1px solid black;
        color: white;       
        margin:5px;
        border-radius: 3px;
    }
"""

FLOATING_BAR_QLabel_STYLESHEET = """
    QLabel { 
        align-items: left;
        align: left;
        padding: 5px;
        font-size: 13px;
        font-family: Times;
        background:transparent;
        border: 0px;
        border-radius: 0px;
    }
"""

FLOATING_BAR_QPushButton_STYLESHEET = """
    QPushButton { 
        align-items: right;
        align: right;
        padding: 5px;
        border: 0px;
        border-radius: 0px;
        background: rgba(0, 185, 255, 0.5);
        color: white;
        font-size: 13px;
        font-family: Times;
    }
"""

