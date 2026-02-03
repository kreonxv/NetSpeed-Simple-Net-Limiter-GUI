# NetSpeed — Simple Net Limiter GUI

A lightweight network limiter GUI for Windows that uses Python and WinDivert (via `pydivert`).

**Features**
- Simple tray-enabled GUI to limit or monitor network bandwidth
- Built with `customtkinter` for a modern UI

**Prerequisites**
- Python 3.10
- Administrator privileges to capture and modify network packets

**Installation**
1. Create and activate a virtual environment:

```powershell
python -m venv env
.\env\Scripts\Activate.ps1
```

2. Install dependencies:

```powershell
pip install -r requirements.txt
```

**Running**
- From the project folder run:

```powershell
python GUI.py
```

- Or use the provided `NetSpeed.bat` if present.

**Notes & Troubleshooting**
- `pydivert` requires administrator rights. Run the script or terminal as Administrator when testing.
- If tray icons do not appear, ensure `pystray` and your system tray support the required icon backends.

**Dependencies**
- See [requirements.txt](requirements.txt) for the main packages used.

**License & Disclaimer**
Use this tool at your own risk. Intercepting or modifying network traffic may violate network policies. This project provides no warranty.

---
If you want, I can also add a short usage guide, example screenshots, or a troubleshooting section specific to WinDivert installation.
