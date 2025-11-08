#!/bin/bash
# ULP Sorter GUI Launcher

# Check if customtkinter is installed
python3 -c "import customtkinter" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "Installing required dependencies..."
    pip install customtkinter pillow
fi

# Launch the GUI
python3 ulptool_gui.py
