from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
from enum import Enum
import os
import bcrypt
import jwt
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

# --------------------------------------------------
# ENV
# --------------------------------------------------
load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
SECRET_KEY = os.getenv("SECRET_KEY", "change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

# --------------------------------------------------
# APP
# --------------------------------------------------
app = FastAPI(title="Gyana Education Hub API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# --------------------------------------------------
# ENUMS
# --------------------------------------------------
class CourseEnum(str, Enum):
    BSc = "B.Sc"
    BA = "B.A"
    BCom = "B.Com"
    BCA = "B.C.A"

class SemesterEnum(str, Enum):
    sem1 = "1"
    sem2 = "2"
    sem3 = "3"
    sem4 = "4"
    sem5 = "5"
    sem6 = "6"
    sem7 = "7"
    sem8 = "8"

class PriorityEnum(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"

# --------------------------------------------------
# MODELS
# --------------------------------------------------
class LoginRequest(BaseModel):
    username: str
    password: str

class NotificationCreate(BaseModel):
    title: str
    message: str
    exam_date: Optional[str] = None
    exam_name: Optional[str] = None
    priority: PriorityEnum = PriorityEnum.medium

class NotificationUpdate(BaseModel):
    title: Optional[str] = None
    message: Optional[str] = None
    exam_date: Optional[str] = None
    exam_name: Optional[str] = None
    priority: Optional[PriorityEnum] = None
    is_active: Optional[bool] = None

class NoteCreate(BaseModel):
    title: str
    description: Optional[str] = None
    pdf_url: str
    course: CourseEnum
    semester: SemesterEnum
    topic: str
    file_size_kb: Optional[int] = None

class NoteUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    pdf_url: Optional[str] = None
    course: Optional[CourseEnum] = None
    semester: Optional[SemesterEnum] = None
    topic: Optional[str] = None
    file_size_kb: Optional[int] = None
    is_active: Optional[bool] = None

class VideoLectureCreate(BaseModel):
    title: str
    description: Optional[str] = None
    youtube_url: str
    course: CourseEnum
    semester: SemesterEnum
    topic: str
    duration_minutes: Optional[int] = None

class VideoLectureUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    youtube_url: Optional[str] = None
    course: Optional[CourseEnum] = None
    semester: Optional[SemesterEnum] = None
    topic: Optional[str] = None
    duration_minutes: Optional[int] = None
    is_active: Optional[bool] = None

# --------------------------------------------------
# DATABASE HELPERS
# --------------------------------------------------
def get_db_connection():
    try:
        return psycopg2.connect(DATABASE_URL, sslmode="require")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def execute_query(query, params=None, fetch_one=False, fetch_all=False):
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(query, params)

        if fetch_one:
            result = cur.fetchone()
        elif fetch_all:
            result = cur.fetchall()
        else:
            conn.commit()
            result = None

        cur.close()
        return result
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()

# --------------------------------------------------
# AUTH
# --------------------------------------------------
def create_access_token(data: dict):
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# --------------------------------------------------
# ROUTES
# --------------------------------------------------
@app.get("/")
def root():
    return {"status": "online"}

# ---------------- LOGIN ----------------
@app.post("/api/auth/login")
def login(data: LoginRequest):
    user = execute_query(
        "SELECT id, username, password_hash FROM admin_users WHERE username=%s AND is_active IS TRUE",
        (data.username,),
        fetch_one=True
    )

    if not user or not bcrypt.checkpw(data.password.encode(), user["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": user["username"], "user_id": user["id"]})
    return {"access_token": token, "token_type": "bearer"}

# ---------------- NOTIFICATIONS ----------------
@app.get("/api/notifications")
def get_notifications():
    return execute_query("SELECT * FROM notifications ORDER BY created_at DESC", fetch_all=True)

@app.post("/api/notifications")
def create_notification(data: NotificationCreate, username=Depends(verify_token)):
    user = execute_query("SELECT id FROM admin_users WHERE username=%s", (username,), fetch_one=True)

    result = execute_query(
        """
        INSERT INTO notifications (title, message, exam_date, exam_name, priority, created_by)
        VALUES (%s,%s,%s,%s,%s,%s)
        RETURNING id
        """,
        (data.title, data.message, data.exam_date, data.exam_name, data.priority.value, user["id"]),
        fetch_one=True
    )
    return {"id": result["id"]}

# ---------------- NOTES ----------------
@app.post("/api/notes")
def create_note(data: NoteCreate, username=Depends(verify_token)):
    user = execute_query("SELECT id FROM admin_users WHERE username=%s", (username,), fetch_one=True)

    result = execute_query(
        """
        INSERT INTO notes (title, description, pdf_url, course, semester, topic, file_size_kb, created_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING id
        """,
        (data.title, data.description, data.pdf_url, data.course.value,
         data.semester.value, data.topic, data.file_size_kb, user["id"]),
        fetch_one=True
    )
    return {"id": result["id"]}

# ---------------- VIDEOS ----------------
@app.post("/api/videos")
def create_video(data: VideoLectureCreate, username=Depends(verify_token)):
    user = execute_query("SELECT id FROM admin_users WHERE username=%s", (username,), fetch_one=True)

    video_id = data.youtube_url.split("v=")[-1].split("&")[0]
    thumbnail = f"https://img.youtube.com/vi/{video_id}/maxresdefault.jpg"

    result = execute_query(
        """
        INSERT INTO video_lectures
        (title, description, youtube_url, thumbnail_url, course, semester, topic, duration_minutes, created_by)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING id
        """,
        (data.title, data.description, data.youtube_url, thumbnail,
         data.course.value, data.semester.value, data.topic, data.duration_minutes, user["id"]),
        fetch_one=True
    )
    return {"id": result["id"]}

# --------------------------------------------------
# VERCEL ENTRY
# --------------------------------------------------
handler = app