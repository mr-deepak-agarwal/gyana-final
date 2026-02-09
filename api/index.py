from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime, timedelta
import mysql.connector
from mysql.connector import Error
import bcrypt
import jwt
import os
from enum import Enum

# Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440

# Database configuration
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'gyana_edu'),
    'ssl_disabled': False
}

app = FastAPI(title="Gyana Education Hub API", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Enums
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

# Pydantic Models
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

# Database helper functions
def get_db_connection():
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Database connection error: {str(e)}")

def execute_query(query: str, params: tuple = None, fetch_one: bool = False, fetch_all: bool = False):
    connection = get_db_connection()
    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params or ())
        
        if fetch_one:
            result = cursor.fetchone()
        elif fetch_all:
            result = cursor.fetchall()
        else:
            connection.commit()
            result = cursor.lastrowid
        
        cursor.close()
        return result
    except Error as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection.is_connected():
            connection.close()

# Authentication functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# Routes
@app.get("/")
@app.get("/api")
def read_root():
    return {"message": "Gyana Education Hub API", "version": "1.0.0", "status": "online"}

# Authentication
@app.post("/api/auth/login")
def login(credentials: LoginRequest):
    query = "SELECT id, username, password_hash FROM admin_users WHERE username = %s AND is_active = TRUE"
    user = execute_query(query, (credentials.username,), fetch_one=True)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    if not bcrypt.checkpw(credentials.password.encode('utf-8'), user['password_hash'].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    update_query = "UPDATE admin_users SET last_login = %s WHERE id = %s"
    execute_query(update_query, (datetime.now(), user['id']))
    
    access_token = create_access_token(data={"sub": user['username'], "user_id": user['id']})
    return {"access_token": access_token, "token_type": "bearer", "username": user['username']}

# Notifications CRUD
@app.get("/api/notifications")
def get_notifications(is_active: Optional[bool] = True):
    query = """
        SELECT n.*, a.username as created_by_name 
        FROM notifications n 
        LEFT JOIN admin_users a ON n.created_by = a.id 
        WHERE n.is_active = %s OR %s IS NULL
        ORDER BY n.created_at DESC
    """
    notifications = execute_query(query, (is_active, is_active), fetch_all=True)
    return notifications

@app.post("/api/notifications")
def create_notification(notification: NotificationCreate, username: str = Depends(verify_token)):
    user = execute_query("SELECT id FROM admin_users WHERE username = %s", (username,), fetch_one=True)
    
    query = """
        INSERT INTO notifications (title, message, exam_date, exam_name, priority, created_by)
        VALUES (%s, %s, %s, %s, %s, %s)
    """
    notification_id = execute_query(query, (
        notification.title,
        notification.message,
        notification.exam_date,
        notification.exam_name,
        notification.priority,
        user['id']
    ))
    
    return {"id": notification_id, "message": "Notification created successfully"}

@app.put("/api/notifications/{notification_id}")
def update_notification(notification_id: int, notification: NotificationUpdate, username: str = Depends(verify_token)):
    updates = []
    params = []
    
    if notification.title:
        updates.append("title = %s")
        params.append(notification.title)
    if notification.message:
        updates.append("message = %s")
        params.append(notification.message)
    if notification.exam_date:
        updates.append("exam_date = %s")
        params.append(notification.exam_date)
    if notification.exam_name:
        updates.append("exam_name = %s")
        params.append(notification.exam_name)
    if notification.priority:
        updates.append("priority = %s")
        params.append(notification.priority)
    if notification.is_active is not None:
        updates.append("is_active = %s")
        params.append(notification.is_active)
    
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    params.append(notification_id)
    query = f"UPDATE notifications SET {', '.join(updates)} WHERE id = %s"
    execute_query(query, tuple(params))
    
    return {"message": "Notification updated successfully"}

@app.delete("/api/notifications/{notification_id}")
def delete_notification(notification_id: int, username: str = Depends(verify_token)):
    query = "DELETE FROM notifications WHERE id = %s"
    execute_query(query, (notification_id,))
    return {"message": "Notification deleted successfully"}

# Notes CRUD
@app.get("/api/notes")
def get_notes(
    course: Optional[CourseEnum] = None,
    semester: Optional[SemesterEnum] = None,
    topic: Optional[str] = None,
    is_active: Optional[bool] = True
):
    query = """
        SELECT n.*, a.username as created_by_name 
        FROM notes n 
        LEFT JOIN admin_users a ON n.created_by = a.id 
        WHERE (n.is_active = %s OR %s IS NULL)
        AND (n.course = %s OR %s IS NULL)
        AND (n.semester = %s OR %s IS NULL)
        AND (n.topic LIKE %s OR %s IS NULL)
        ORDER BY n.created_at DESC
    """
    topic_param = f"%{topic}%" if topic else None
    notes = execute_query(query, (
        is_active, is_active,
        course, course,
        semester, semester,
        topic_param, topic
    ), fetch_all=True)
    return notes

@app.post("/api/notes")
def create_note(note: NoteCreate, username: str = Depends(verify_token)):
    user = execute_query("SELECT id FROM admin_users WHERE username = %s", (username,), fetch_one=True)
    
    query = """
        INSERT INTO notes (title, description, pdf_url, course, semester, topic, file_size_kb, created_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """
    note_id = execute_query(query, (
        note.title,
        note.description,
        note.pdf_url,
        note.course,
        note.semester,
        note.topic,
        note.file_size_kb,
        user['id']
    ))
    
    return {"id": note_id, "message": "Note created successfully"}

@app.put("/api/notes/{note_id}")
def update_note(note_id: int, note: NoteUpdate, username: str = Depends(verify_token)):
    updates = []
    params = []
    
    for field, value in note.dict(exclude_unset=True).items():
        if value is not None:
            updates.append(f"{field} = %s")
            params.append(value)
    
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    params.append(note_id)
    query = f"UPDATE notes SET {', '.join(updates)} WHERE id = %s"
    execute_query(query, tuple(params))
    
    return {"message": "Note updated successfully"}

@app.delete("/api/notes/{note_id}")
def delete_note(note_id: int, username: str = Depends(verify_token)):
    query = "DELETE FROM notes WHERE id = %s"
    execute_query(query, (note_id,))
    return {"message": "Note deleted successfully"}

@app.post("/api/notes/{note_id}/increment-download")
def increment_note_download(note_id: int):
    query = "UPDATE notes SET downloads = downloads + 1 WHERE id = %s"
    execute_query(query, (note_id,))
    return {"message": "Download count incremented"}

# Video Lectures CRUD
@app.get("/api/videos")
def get_videos(
    course: Optional[CourseEnum] = None,
    semester: Optional[SemesterEnum] = None,
    topic: Optional[str] = None,
    is_active: Optional[bool] = True
):
    query = """
        SELECT v.*, a.username as created_by_name 
        FROM video_lectures v 
        LEFT JOIN admin_users a ON v.created_by = a.id 
        WHERE (v.is_active = %s OR %s IS NULL)
        AND (v.course = %s OR %s IS NULL)
        AND (v.semester = %s OR %s IS NULL)
        AND (v.topic LIKE %s OR %s IS NULL)
        ORDER BY v.created_at DESC
    """
    topic_param = f"%{topic}%" if topic else None
    videos = execute_query(query, (
        is_active, is_active,
        course, course,
        semester, semester,
        topic_param, topic
    ), fetch_all=True)
    return videos

@app.post("/api/videos")
def create_video(video: VideoLectureCreate, username: str = Depends(verify_token)):
    user = execute_query("SELECT id FROM admin_users WHERE username = %s", (username,), fetch_one=True)
    
    thumbnail_url = None
    if "youtube.com" in video.youtube_url or "youtu.be" in video.youtube_url:
        video_id = video.youtube_url.split("v=")[-1].split("&")[0] if "v=" in video.youtube_url else video.youtube_url.split("/")[-1]
        thumbnail_url = f"https://img.youtube.com/vi/{video_id}/maxresdefault.jpg"
    
    query = """
        INSERT INTO video_lectures (title, description, youtube_url, thumbnail_url, course, semester, topic, duration_minutes, created_by)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    video_id = execute_query(query, (
        video.title,
        video.description,
        video.youtube_url,
        thumbnail_url,
        video.course,
        video.semester,
        video.topic,
        video.duration_minutes,
        user['id']
    ))
    
    return {"id": video_id, "message": "Video lecture created successfully"}

@app.put("/api/videos/{video_id}")
def update_video(video_id: int, video: VideoLectureUpdate, username: str = Depends(verify_token)):
    updates = []
    params = []
    
    for field, value in video.dict(exclude_unset=True).items():
        if value is not None:
            updates.append(f"{field} = %s")
            params.append(value)
    
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    params.append(video_id)
    query = f"UPDATE video_lectures SET {', '.join(updates)} WHERE id = %s"
    execute_query(query, tuple(params))
    
    return {"message": "Video lecture updated successfully"}

@app.delete("/api/videos/{video_id}")
def delete_video(video_id: int, username: str = Depends(verify_token)):
    query = "DELETE FROM video_lectures WHERE id = %s"
    execute_query(query, (video_id,))
    return {"message": "Video lecture deleted successfully"}

@app.post("/api/videos/{video_id}/increment-view")
def increment_video_view(video_id: int):
    query = "UPDATE video_lectures SET views = views + 1 WHERE id = %s"
    execute_query(query, (video_id,))
    return {"message": "View count incremented"}

# Get unique topics
@app.get("/api/topics")
def get_topics():
    notes_query = "SELECT DISTINCT topic FROM notes WHERE is_active = TRUE"
    videos_query = "SELECT DISTINCT topic FROM video_lectures WHERE is_active = TRUE"
    
    notes_topics = execute_query(notes_query, fetch_all=True)
    videos_topics = execute_query(videos_query, fetch_all=True)
    
    all_topics = set()
    for item in notes_topics:
        all_topics.add(item['topic'])
    for item in videos_topics:
        all_topics.add(item['topic'])
    
    return {"topics": sorted(list(all_topics))}

# Vercel handler
handler = app
