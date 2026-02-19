# Static-analyzer 🔍
Static analyzer for multiple types of files.
## Supported types📋:
1. Images:
 - PNG
 - JPG/JPEG
 - GIF
 - BMP
2. Office:
 - OOXML
 - OLE
3. Archives:
 - ZIP
4. PDF
5. PE
6. Text/Script

---
## How to use ❔
1. You should have python(and FastAPI) and any compiler for C++(e.g. msys) installed on your device.
2. Compile C++ module to 'build' folder, and ideally name your solution "scannerVB". However if you don't want to, change name of the module in mainVB.py to yours.
3. Start the program using:
 - For Frontend: py -m http.server 5050
 - For Backend: uvicorn mainVB:app --reload
4. Proceed with instruction on the site.