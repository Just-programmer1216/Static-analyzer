# Static-analyzer 🔍
Static analyzer for multiple types of files.
## Supported types📋:
- Images:
 - PNG
 - JPG/JPEG
 - GIF
 - BMP
- Office:
 - OOXML
 - OLE
- Archives:
 - ZIP
- PDF
- PE
- Text/Script

---
## How to use ❔
1. You should have python(and FastAPI) and any compiler for C++(e.g. msys) installed on your device.
2. Compile C++ module to 'build' folder, and ideally name your solution "scannerVB". However if you don't want to, change name of the module in mainVB.py to yours.
3. Start the program using:
 1. For Frontend: py -m http.server 5050
 2. For Backend: uvicorn mainVB:app --reload
4. Proceed with instruction on the site.