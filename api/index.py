from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import base64
import time
import os

app = FastAPI(title="RedStar Forum", docs_url=None, redoc_url=None)

THREADS = []
USERS = {}  # public_key_b64 -> {username, avatar_url, bio, reputation}

class RegisterModel(BaseModel):
    public_key_b64: str

class ProfileModel(BaseModel):
    public_key_b64: str
    username: str
    avatar_url: str
    bio: str

class ThreadModel(BaseModel):
    public_key_b64: str
    category: str
    title: str
    content: str
    timestamp: int
    signature_b64: str

class ReplyModel(BaseModel):
    public_key_b64: str
    thread_id: int
    content: str
    timestamp: int
    signature_b64: str

class ThanksModel(BaseModel):
    public_key_b64: str
    thread_id: int
    reply_index: int = -1

# --- Statik Dosyalar ve Kök Dizin Yönlendirmesi (Render / Vercel İçin) ---
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def serve_index():
    index_path = os.path.join("static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"error": "index.html bulunamadı"}
# -----------------------------------------------------------------------

@app.post("/api/register")
def register_user(user: RegisterModel):
    if user.public_key_b64 not in USERS:
        USERS[user.public_key_b64] = {
            "username": "Anonim_" + user.public_key_b64[:6],
            "avatar_url": "https://i.etsystatic.com/24007829/r/il/57906b/4708413160/il_800x800.4708413160_c8ip.jpg",
            "bio": "Aynılar aynı yerdedir ayrılar ayrı yerde.",
            "reputation": 0
        }
    return {"status": "success", "profile": USERS[user.public_key_b64]}

@app.post("/api/profile")
def update_profile(profile: ProfileModel):
    if profile.public_key_b64 not in USERS:
        raise HTTPException(status_code=401, detail="Unauthorized.")
    
    clean_name = profile.username.strip()[:20]
    clean_avatar = profile.avatar_url.strip()
    clean_bio = profile.bio.strip()[:100]

    if not clean_name:
        raise HTTPException(status_code=400, detail="Invalid username.")

    current_rep = USERS[profile.public_key_b64].get("reputation", 0)
    USERS[profile.public_key_b64] = {
        "username": clean_name,
        "avatar_url": clean_avatar if clean_avatar else "https://i.etsystatic.com/24007829/r/il/57906b/4708413160/il_800x800.4708413160_c8ip.jpg",
        "bio": clean_bio,
        "reputation": current_rep
    }
    return {"status": "success", "profile": USERS[profile.public_key_b64]}

@app.post("/api/threads")
def create_thread(thread: ThreadModel):
    if thread.public_key_b64 not in USERS:
        raise HTTPException(status_code=401, detail="Unauthorized.")
    if abs(int(time.time()) - thread.timestamp) > 60:
        raise HTTPException(status_code=400, detail="Stale timestamp.")

    try:
        pub_key_bytes = base64.b64decode(thread.public_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        message = f"{thread.category}:{thread.title}:{thread.content}:{thread.timestamp}".encode('utf-8')
        public_key.verify(base64.b64decode(thread.signature_b64), message)
    except (InvalidSignature, Exception):
        raise HTTPException(status_code=403, detail="Invalid signature.")

    user_info = USERS.get(thread.public_key_b64, {"username": "Anonim", "avatar_url": "", "bio": "", "reputation": 0})
    thread_data = {
        "id": len(THREADS),
        "author_pub": thread.public_key_b64,
        "author": user_info,
        "category": thread.category,
        "title": thread.title,
        "content": thread.content,
        "timestamp": thread.timestamp,
        "thanks_count": 0,
        "replies": []
    }
    THREADS.append(thread_data)
    return {"status": "success", "thread_id": thread_data["id"]}

@app.post("/api/reply")
def create_reply(reply: ReplyModel):
    if reply.public_key_b64 not in USERS:
        raise HTTPException(status_code=401, detail="Unauthorized.")
    if reply.thread_id < 0 or reply.thread_id >= len(THREADS):
        raise HTTPException(status_code=404, detail="Thread not found.")
    if abs(int(time.time()) - reply.timestamp) > 60:
        raise HTTPException(status_code=400, detail="Stale timestamp.")

    try:
        pub_key_bytes = base64.b64decode(reply.public_key_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        message = f"{reply.thread_id}:{reply.content}:{reply.timestamp}".encode('utf-8')
        public_key.verify(base64.b64decode(reply.signature_b64), message)
    except (InvalidSignature, Exception):
        raise HTTPException(status_code=403, detail="Invalid signature.")

    user_info = USERS.get(reply.public_key_b64, {"username": "Anonim", "avatar_url": "", "bio": "", "reputation": 0})
    reply_data = {
        "author_pub": reply.public_key_b64,
        "author": user_info,
        "content": reply.content,
        "timestamp": reply.timestamp,
        "thanks_count": 0
    }
    THREADS[reply.thread_id]["replies"].append(reply_data)
    return {"status": "success"}

@app.post("/api/thanks")
def add_thanks(data: ThanksModel):
    if data.thread_id < 0 or data.thread_id >= len(THREADS):
        raise HTTPException(status_code=404, detail="Thread not found.")
    
    thread = THREADS[data.thread_id]
    if data.reply_index == -1:
        thread["thanks_count"] += 1
        target_author_pub = thread["author_pub"]
    else:
        if data.reply_index < 0 or data.reply_index >= len(thread["replies"]):
            raise HTTPException(status_code=404, detail="Reply not found.")
        reply = thread["replies"][data.reply_index]
        reply["thanks_count"] += 1
        target_author_pub = reply["author_pub"]

    if target_author_pub in USERS:
        USERS[target_author_pub]["reputation"] += 1

    return {"status": "success"}

@app.get("/api/threads")
def get_threads():
    return [{
        "id": t["id"], 
        "category": t["category"], 
        "title": t["title"], 
        "content": t["content"],
        "author": t["author"], 
        "timestamp": t["timestamp"], 
        "thanks_count": t["thanks_count"],
        "reply_count": len(t["replies"])
    } for t in THREADS]

@app.get("/api/threads/{thread_id}")
def get_thread(thread_id: int):
    if thread_id < 0 or thread_id >= len(THREADS):
        raise HTTPException(status_code=404, detail="Thread not found.")
    return THREADS[thread_id]
