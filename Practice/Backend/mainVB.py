from fastapi import FastAPI, UploadFile, File, HTTPException
from typing import List
from fastapi.middleware.cors import CORSMiddleware
import subprocess
import tempfile
import os
import json
import shutil

MAX_TOTAL_SIZE = 200 * 1024 * 1024

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SCANNER_PATH = os.path.join(BASE_DIR, "Backend", "Scanner", "build", "scannerVB.exe")


class BodySizeLimitMiddleware:
    def __init__(self, app, max_body_size: int):
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        received = 0
        chunks = []
        more_body = True

        while more_body:
            message = await receive()

            if message["type"] != "http.request":
                break

            body = message.get("body", b"")
            if body:
                received += len(body)
                if received > self.max_body_size:
                    resp = json.dumps({"detail": "Total upload size exceeds 200 MB limit."}).encode("utf-8")
                    headers = [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(resp)).encode("ascii")),
                    ]
                    await send({"type": "http.response.start", "status": 413, "headers": headers})
                    await send({"type": "http.response.body", "body": resp, "more_body": False})
                    return

                chunks.append(body)

            more_body = message.get("more_body", False)

        full_body = b"".join(chunks)

        sent = False

        async def receive_replay():
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": full_body, "more_body": False}

        await self.app(scope, receive_replay, send)


app = FastAPI()

app.add_middleware(BodySizeLimitMiddleware, max_body_size=MAX_TOTAL_SIZE)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/upload/")
async def upload_files(file: List[UploadFile] = File(...)):
    if not os.path.isfile(SCANNER_PATH):
        raise HTTPException(status_code=500, detail="Scanner binary not found.")

    results = []
    tmp_root = tempfile.mkdtemp(prefix="scan_")

    try:
        for uploaded_file in file:
            original_name = uploaded_file.filename or "upload.bin"
            safe_name = os.path.basename(original_name)

            # Unique per-file directory inside request root (no uuid needed)
            per_file_dir = tempfile.mkdtemp(prefix="f_", dir=tmp_root)
            tmp_path = os.path.join(per_file_dir, safe_name)

            try:
                with open(tmp_path, "wb") as out:
                    while True:
                        chunk = await uploaded_file.read(1024 * 1024)
                        if not chunk:
                            break
                        out.write(chunk)

                await uploaded_file.close()

                proc = subprocess.run(
                    [SCANNER_PATH, tmp_path],
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if proc.returncode != 0:
                    err = (proc.stderr or "").strip() or "Scanner returned non-zero exit code."
                    raise HTTPException(status_code=500, detail=f"Scanner error: {err}")

                try:
                    data = json.loads(proc.stdout)
                except json.JSONDecodeError:
                    raise HTTPException(status_code=500, detail="Invalid scanner output")

                results.append(data)

            except subprocess.TimeoutExpired:
                raise HTTPException(status_code=504, detail="Scanner timeout")

            finally:
                try:
                    await uploaded_file.close()
                except Exception:
                    pass
                shutil.rmtree(per_file_dir, ignore_errors=True)

    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

    return {"results": results}