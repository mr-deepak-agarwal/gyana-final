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
import traceback

# --------------------------------------------------
# ENV
# --------------------------------------------------

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

class StudentSubmission(BaseModel):
    name: str
    email: str
    mobile: str
    currentCourse: str
    collegeName: Optional[str] = None
    class_year: Optional[str] = None
    goals: Optional[str] = None
    skills: Optional[str] = None
    skillswant: Optional[str] = None

# --------------------------------------------------
# DATABASE HELPERS
# --------------------------------------------------
def get_db_connection():
    try:
        if not DATABASE_URL:
            raise HTTPException(status_code=500, detail="DATABASE_URL not configured")
        return psycopg2.connect(DATABASE_URL, sslmode="require")
    except Exception as e:
        print(f"Database connection error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Database connection failed: {str(e)}")

def execute_query(query, params=None, fetch_one=False, fetch_all=False):
    conn = get_db_connection()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        print(f"Executing query: {query}")
        print(f"With params: {params}")
        
        cur.execute(query, params)
        
        # Determine if this is a write operation
        is_write = query.strip().upper().startswith(('INSERT', 'UPDATE', 'DELETE'))

        if fetch_one:
            result = cur.fetchone()
        elif fetch_all:
            result = cur.fetchall()
        else:
            result = None
        
        # Commit if it's a write operation
        if is_write:
            conn.commit()
            print("Transaction committed")

        cur.close()
        print(f"Query executed successfully. Result: {result}")
        return result
    except Exception as e:
        conn.rollback()
        print(f"Database error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
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
    except Exception as e:
        print(f"Token verification error: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid token")

# --------------------------------------------------
# ROUTES
# --------------------------------------------------
@app.get("/")
@app.get("/api")
def root():
    return {"status": "online", "message": "Gyana Education Hub API", "database_configured": DATABASE_URL is not None}

# ---------------- LOGIN ----------------
@app.post("/api/auth/login")
def login(data: LoginRequest):
    try:
        user = execute_query(
            "SELECT id, username, password_hash FROM admin_users WHERE username=%s AND is_active IS TRUE",
            (data.username,),
            fetch_one=True
        )

        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        if not bcrypt.checkpw(data.password.encode(), user["password_hash"].encode()):
            raise HTTPException(status_code=401, detail="Invalid password")

        token = create_access_token({"sub": user["username"], "user_id": user["id"]})
        return {"access_token": token, "token_type": "bearer", "username": user["username"]}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Login error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

# ---------------- NOTIFICATIONS ----------------
@app.get("/api/notifications")
def get_notifications(is_active: Optional[bool] = None):
    try:
        if is_active is None:
            query = "SELECT * FROM notifications ORDER BY created_at DESC"
            params = None
        else:
            query = "SELECT * FROM notifications WHERE is_active=%s ORDER BY created_at DESC"
            params = (is_active,)
        result = execute_query(query, params, fetch_all=True)
        return result or []
    except Exception as e:
        print(f"Get notifications error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch notifications: {str(e)}")

@app.post("/api/notifications")
def create_notification(data: NotificationCreate, username=Depends(verify_token)):
    try:
        print(f"Creating notification: {data}")
        print(f"Username from token: {username}")
        
        user = execute_query("SELECT id FROM admin_users WHERE username=%s", (username,), fetch_one=True)
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        print(f"User found: {user}")
        
        # Convert empty strings to None for optional fields
        exam_date = data.exam_date if data.exam_date else None
        exam_name = data.exam_name if data.exam_name else None

        result = execute_query(
            """
            INSERT INTO notifications (title, message, exam_date, exam_name, priority, created_by)
            VALUES (%s,%s,%s,%s,%s,%s)
            RETURNING id
            """,
            (data.title, data.message, exam_date, exam_name, data.priority.value, user["id"]),
            fetch_one=True
        )
        
        print(f"Notification created with ID: {result['id']}")
        return {"id": result["id"], "message": "Notification created successfully"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Create notification error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=f"Failed to create notification: {str(e)}")

@app.put("/api/notifications/{notification_id}")
def update_notification(notification_id: int, data: NotificationUpdate, username=Depends(verify_token)):
    try:
        updates = []
        params = []
        
        if data.title:
            updates.append("title = %s")
            params.append(data.title)
        if data.message:
            updates.append("message = %s")
            params.append(data.message)
        
        # Allow explicitly setting exam_date and exam_name to None
        if data.exam_date is not None:
            updates.append("exam_date = %s")
            params.append(data.exam_date if data.exam_date else None)
        if data.exam_name is not None:
            updates.append("exam_name = %s")
            params.append(data.exam_name if data.exam_name else None)
            
        if data.priority:
            updates.append("priority = %s")
            params.append(data.priority.value)
        if data.is_active is not None:
            updates.append("is_active = %s")
            params.append(data.is_active)
        
        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")
        
        params.append(notification_id)
        query = f"UPDATE notifications SET {', '.join(updates)} WHERE id = %s"
        execute_query(query, tuple(params))
        
        return {"message": "Notification updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Update notification error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update notification: {str(e)}")

@app.delete("/api/notifications/{notification_id}")
def delete_notification(notification_id: int, username=Depends(verify_token)):
    try:
        execute_query("DELETE FROM notifications WHERE id = %s", (notification_id,))
        return {"message": "Notification deleted successfully"}
    except Exception as e:
        print(f"Delete notification error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete notification: {str(e)}")

# ---------------- STUDENT SUBMISSIONS ----------------
@app.post("/api/submit")
def submit_student_form(data: StudentSubmission):
    try:
        result = execute_query(
            """
            INSERT INTO student_submissions 
            (name, email, mobile, course, college_name, class_year, goals, current_skills, skills_to_learn)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (data.name, data.email, data.mobile, data.currentCourse, data.collegeName,
             data.class_year, data.goals, data.skills, data.skillswant),
            fetch_one=True
        )
        return {"id": result["id"], "message": "Form submitted successfully"}
    except Exception as e:
        print(f"Submit form error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to submit form: {str(e)}")

# ---------------- NOTES ----------------
@app.get("/api/notes")
def get_notes(
    course: Optional[str] = None,
    semester: Optional[str] = None,
    topic: Optional[str] = None,
    is_active: Optional[bool] = None
):
    try:
        query = "SELECT * FROM notes WHERE 1=1"
        params = []
        
        if is_active is not None:
            query += " AND is_active = %s"
            params.append(is_active)
        if course:
            query += " AND course = %s"
            params.append(course)
        if semester:
            query += " AND semester = %s"
            params.append(semester)
        if topic:
            query += " AND topic ILIKE %s"
            params.append(f"%{topic}%")
        
        query += " ORDER BY created_at DESC"
        return execute_query(query, tuple(params) if params else None, fetch_all=True) or []
    except Exception as e:
        print(f"Get notes error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch notes: {str(e)}")

@app.post("/api/notes")
def create_note(data: NoteCreate, username=Depends(verify_token)):
    try:
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
        return {"id": result["id"], "message": "Note created successfully"}
    except Exception as e:
        print(f"Create note error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create note: {str(e)}")

@app.put("/api/notes/{note_id}")
def update_note(note_id: int, data: NoteUpdate, username=Depends(verify_token)):
    try:
        updates = []
        params = []
        
        if data.title:
            updates.append("title = %s")
            params.append(data.title)
        if data.description:
            updates.append("description = %s")
            params.append(data.description)
        if data.pdf_url:
            updates.append("pdf_url = %s")
            params.append(data.pdf_url)
        if data.course:
            updates.append("course = %s")
            params.append(data.course.value)
        if data.semester:
            updates.append("semester = %s")
            params.append(data.semester.value)
        if data.topic:
            updates.append("topic = %s")
            params.append(data.topic)
        if data.file_size_kb is not None:
            updates.append("file_size_kb = %s")
            params.append(data.file_size_kb)
        if data.is_active is not None:
            updates.append("is_active = %s")
            params.append(data.is_active)
        
        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")
        
        params.append(note_id)
        query = f"UPDATE notes SET {', '.join(updates)} WHERE id = %s"
        execute_query(query, tuple(params))
        
        return {"message": "Note updated successfully"}
    except Exception as e:
        print(f"Update note error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update note: {str(e)}")

@app.delete("/api/notes/{note_id}")
def delete_note(note_id: int, username=Depends(verify_token)):
    try:
        execute_query("DELETE FROM notes WHERE id = %s", (note_id,))
        return {"message": "Note deleted successfully"}
    except Exception as e:
        print(f"Delete note error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete note: {str(e)}")

@app.post("/api/notes/{note_id}/increment-download")
def increment_note_download(note_id: int):
    try:
        execute_query("UPDATE notes SET downloads = downloads + 1 WHERE id = %s", (note_id,))
        return {"message": "Download count incremented"}
    except Exception as e:
        print(f"Increment download error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to increment download: {str(e)}")

# ---------------- VIDEOS ----------------
@app.get("/api/videos")
def get_videos(
    course: Optional[str] = None,
    semester: Optional[str] = None,
    topic: Optional[str] = None,
    is_active: Optional[bool] = None
):
    try:
        query = "SELECT * FROM video_lectures WHERE 1=1"
        params = []
        
        if is_active is not None:
            query += " AND is_active = %s"
            params.append(is_active)
        if course:
            query += " AND course = %s"
            params.append(course)
        if semester:
            query += " AND semester = %s"
            params.append(semester)
        if topic:
            query += " AND topic ILIKE %s"
            params.append(f"%{topic}%")
        
        query += " ORDER BY created_at DESC"
        return execute_query(query, tuple(params) if params else None, fetch_all=True) or []
    except Exception as e:
        print(f"Get videos error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch videos: {str(e)}")

@app.post("/api/videos")
def create_video(data: VideoLectureCreate, username=Depends(verify_token)):
    try:
        user = execute_query("SELECT id FROM admin_users WHERE username=%s", (username,), fetch_one=True)

        # Extract YouTube video ID
        video_id = data.youtube_url.split("v=")[-1].split("&")[0] if "v=" in data.youtube_url else data.youtube_url.split("/")[-1]
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
        return {"id": result["id"], "message": "Video created successfully"}
    except Exception as e:
        print(f"Create video error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create video: {str(e)}")

@app.put("/api/videos/{video_id}")
def update_video(video_id: int, data: VideoLectureUpdate, username=Depends(verify_token)):
    try:
        updates = []
        params = []
        
        if data.title:
            updates.append("title = %s")
            params.append(data.title)
        if data.description:
            updates.append("description = %s")
            params.append(data.description)
        if data.youtube_url:
            updates.append("youtube_url = %s")
            params.append(data.youtube_url)
            # Update thumbnail too
            vid_id = data.youtube_url.split("v=")[-1].split("&")[0] if "v=" in data.youtube_url else data.youtube_url.split("/")[-1]
            updates.append("thumbnail_url = %s")
            params.append(f"https://img.youtube.com/vi/{vid_id}/maxresdefault.jpg")
        if data.course:
            updates.append("course = %s")
            params.append(data.course.value)
        if data.semester:
            updates.append("semester = %s")
            params.append(data.semester.value)
        if data.topic:
            updates.append("topic = %s")
            params.append(data.topic)
        if data.duration_minutes is not None:
            updates.append("duration_minutes = %s")
            params.append(data.duration_minutes)
        if data.is_active is not None:
            updates.append("is_active = %s")
            params.append(data.is_active)
        
        if not updates:
            raise HTTPException(status_code=400, detail="No fields to update")
        
        params.append(video_id)
        query = f"UPDATE video_lectures SET {', '.join(updates)} WHERE id = %s"
        execute_query(query, tuple(params))
        
        return {"message": "Video updated successfully"}
    except Exception as e:
        print(f"Update video error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to update video: {str(e)}")

@app.delete("/api/videos/{video_id}")
def delete_video(video_id: int, username=Depends(verify_token)):
    try:
        execute_query("DELETE FROM video_lectures WHERE id = %s", (video_id,))
        return {"message": "Video deleted successfully"}
    except Exception as e:
        print(f"Delete video error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to delete video: {str(e)}")

@app.post("/api/videos/{video_id}/increment-view")
def increment_video_view(video_id: int):
    try:
        execute_query("UPDATE video_lectures SET views = views + 1 WHERE id = %s", (video_id,))
        return {"message": "View count incremented"}
    except Exception as e:
        print(f"Increment view error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to increment view: {str(e)}")

# ---------------- TOPICS ----------------
@app.get("/api/topics")
def get_topics():
    try:
        notes = execute_query("SELECT DISTINCT topic FROM notes WHERE is_active IS TRUE", fetch_all=True) or []
        videos = execute_query("SELECT DISTINCT topic FROM video_lectures WHERE is_active IS TRUE", fetch_all=True) or []
        
        topics = set()
        for note in notes:
            if note and note.get("topic"):
                topics.add(note["topic"])
        for video in videos:
            if video and video.get("topic"):
                topics.add(video["topic"])
        
        return {"topics": sorted(list(topics))}
    except Exception as e:
        print(f"Get topics error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch topics: {str(e)}")