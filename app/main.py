from sqlalchemy.orm import Session
# --- FastAPI app and templates initialization ---
from fastapi import FastAPI, Request, Form, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
import csv
import io
import threading
import time
import secrets as pysecrets
import hashlib
import logging
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from .config import settings
from .db import get_db
from .models import Base, User, RegistrationCode

app = FastAPI()
templates = Jinja2Templates(directory="app/templates")


# Configure logging
logging.basicConfig(level=logging.INFO)
security = HTTPBasic()

# Try database initialization, but don't crash if DB is unavailable
try:
    from sqlalchemy import create_engine
    engine = create_engine(settings.db_url)
    from .models import Base
    try:
        Base.metadata.create_all(bind=engine)
        logging.info("Database tables checked/created successfully.")
    except Exception as dbinit:
        logging.warning(f"Database table creation failed: {dbinit}. App will still start.")
except Exception as e:
    logging.warning(f"Database unavailable at startup: {e}. App will still start.")

# --- Utility functions ---
def audit_log(event: str):
    with open("audit.log", "a") as f:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {event}\n")

def hash_answer(answer: str) -> str:
    return hashlib.sha256(answer.encode()).hexdigest()

def verify_admin(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = pysecrets.compare_digest(credentials.username, getattr(settings, "admin_username", "admin"))
    correct_password = pysecrets.compare_digest(credentials.password, getattr(settings, "admin_password", "adminpass"))
    if not (correct_username and correct_password):
        raise Exception("Invalid admin credentials")
    return True

from fastapi import status
from .ad_utils import get_ad_connection
def check_user_in_ad(ad_account_id: str) -> bool:
    # Try both AD servers
    for server, cert in zip(settings.ad_servers, settings.ad_certs):
        try:
            conn = get_ad_connection(server, cert, settings.ad_username, settings.ad_password)
            search_base = settings.ad_ou
            search_filter = f"(sAMAccountName={ad_account_id})"
            conn.search(search_base, search_filter, attributes=['sAMAccountName'])
            if conn.entries:
                return True
        except Exception:
            continue
    return False
# Admin reporting: view all users
@app.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request, db: Session = Depends(get_db), auth: bool = Depends(verify_admin)):
    users = db.query(User).all()
    return templates.TemplateResponse("admin_users.html", {"request": request, "users": users})

# Admin reporting: download users as CSV
@app.get("/admin/users.csv")
def admin_users_csv(db: Session = Depends(get_db), auth: bool = Depends(verify_admin)):
    users = db.query(User).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "first_name", "last_name", "ad_account_id", "is_approved"])
    for u in users:
        writer.writerow([u.id, u.first_name, u.last_name, u.ad_account_id, u.is_approved])
    output.seek(0)
    return StreamingResponse(output, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=users.csv"})

# Admin reporting: view all registration codes
@app.get("/admin/codes", response_class=HTMLResponse)
def admin_codes(request: Request, db: Session = Depends(get_db), auth: bool = Depends(verify_admin)):
    codes = db.query(RegistrationCode).all()
    return templates.TemplateResponse("admin_codes.html", {"request": request, "codes": codes})

# Admin reporting: download codes as CSV
@app.get("/admin/codes.csv")
def admin_codes_csv(db: Session = Depends(get_db), auth: bool = Depends(verify_admin)):
    codes = db.query(RegistrationCode).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "code", "ad_account_id", "used", "used_by", "created_at", "used_at"])
    for c in codes:
        writer.writerow([c.id, c.code, c.ad_account_id, c.used, c.used_by, c.created_at, c.used_at])
    output.seek(0)
    return StreamingResponse(output, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=codes.csv"})

# Automation: background job to expire unused codes and notify admins (scaffold)

def expire_codes_and_notify():
    while True:
        # Example: expire codes older than 30 days
        try:
            from .db import SessionLocal
            db = SessionLocal()
            from datetime import datetime, timedelta
            expiry = datetime.utcnow() - timedelta(days=30)
            expired = db.query(RegistrationCode).filter(RegistrationCode.used == False, RegistrationCode.created_at < expiry).all()
            for code in expired:
                code.used = True
                db.commit()
                audit_log(f"Code expired: {code.code}")
            db.close()
        except Exception as e:
            logging.warning(f"Background job: Could not connect to DB: {e}")
        time.sleep(86400)  # Run daily

# Start automation in background thread
def can_connect_db():
    try:
        from .db import SessionLocal
        db = SessionLocal()
        db.execute('SELECT 1')
        db.close()
        return True
    except Exception:
        return False

if can_connect_db():
    threading.Thread(target=expire_codes_and_notify, daemon=True).start()
else:
    logging.warning("Background job not started: DB unavailable at startup.")
from sqlalchemy.orm import Session
from sqlalchemy import create_engine



app = FastAPI()
templates = Jinja2Templates(directory="app/templates")

# Database initialization (never crash if DB is down)
try:
    engine = create_engine(settings.db_url)
    Base.metadata.create_all(bind=engine)
    logging.info("Database tables checked/created successfully.")
except Exception as e:
    engine = None
    logging.warning(f"Database unavailable at startup: {e}. App will still start.")

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/password-help", response_class=HTMLResponse)
def password_help(request: Request):
    return templates.TemplateResponse("password_help.html", {"request": request})

# Placeholder endpoints for registration, unlock, status, create user


@app.get("/register", response_class=HTMLResponse)
def register_get(request: Request, code: str = None, db: Session = Depends(get_db)):
    # Require a valid, unused registration code
    if not code:
        return templates.TemplateResponse("register.html", {"request": request, "msg": "Registration code required.", "code": ""})
    reg_code = db.query(RegistrationCode).filter(RegistrationCode.code == code, RegistrationCode.used == False).first()
    if not reg_code:
        return templates.TemplateResponse("register.html", {"request": request, "msg": "Invalid or used registration code.", "code": code})
    return templates.TemplateResponse("register.html", {"request": request, "code": code})




@app.post("/register", response_class=HTMLResponse)
async def register_post(
    request: Request,
    code: str = Form(...),
    first_name: str = Form(...),
    last_name: str = Form(...),
    middle_name: str = Form(None),
    has_ad: str = Form(None),
    ad_account_id: str = Form(None),
    rsa_token_id: str = Form(...),
    home_location: str = Form(...),
    question_1: str = Form(...),
    answer_1: str = Form(...),
    question_2: str = Form(...),
    answer_2: str = Form(...),
    question_3: str = Form(...),
    answer_3: str = Form(...),
    db: Session = Depends(get_db)
):

    # Validate registration code
    try:
        reg_code = db.query(RegistrationCode).filter(RegistrationCode.code == code, RegistrationCode.used == False).first()
        if not reg_code:
            return templates.TemplateResponse("register.html", {"request": request, "msg": "Invalid or used registration code.", "code": code})
        # If code is tied to an AD account, enforce match
        if reg_code.ad_account_id and ad_account_id:
            if reg_code.ad_account_id.lower() != ad_account_id.lower():
                return templates.TemplateResponse("register.html", {"request": request, "msg": "This code is only valid for AD account: %s" % reg_code.ad_account_id, "code": code})
        elif reg_code.ad_account_id and not ad_account_id:
            return templates.TemplateResponse("register.html", {"request": request, "msg": "This code is only valid for AD account: %s" % reg_code.ad_account_id, "code": code})

        # Check if user already exists by AD account ID (if provided)
        if ad_account_id:
            existing = db.query(User).filter(User.ad_account_id == ad_account_id).first()
            if existing:
                return templates.TemplateResponse("register.html", {"request": request, "msg": "User already registered.", "code": code})
            # Check in Active Directory
            if not check_user_in_ad(ad_account_id):
                return templates.TemplateResponse("register.html", {"request": request, "msg": "User not found in Active Directory.", "code": code})

        # Create new user
        user = User(
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            ad_account_id=ad_account_id,
            rsa_token_id=rsa_token_id,
            home_location=home_location,
            question_1=question_1,
            answer_1=hash_answer(answer_1),
            question_2=question_2,
            answer_2=hash_answer(answer_2),
            question_3=question_3,
            answer_3=hash_answer(answer_3),
            is_approved=False
        )
        db.add(user)
        db.commit()
        db.refresh(user)

        # Mark code as used
        reg_code.used = True
        reg_code.used_by = user.id
        from datetime import datetime
        reg_code.used_at = datetime.utcnow()
        db.commit()

        return templates.TemplateResponse("register.html", {"request": request, "msg": "Registration successful! Awaiting approval.", "code": code})
    except Exception as e:
        logging.warning(f"Register endpoint: Could not connect to DB: {e}")
        return templates.TemplateResponse("register.html", {"request": request, "msg": "Database unavailable. Please try again later.", "code": code})
# Admin endpoint to generate registration codes
@app.post("/admin/generate-code", response_class=HTMLResponse)
def generate_code(request: Request, ad_account_id: str = Form(None), db: Session = Depends(get_db), auth: bool = Depends(verify_admin)):
    import secrets
    code = secrets.token_urlsafe(16)
    reg_code = RegistrationCode(code=code, ad_account_id=ad_account_id)
    db.add(reg_code)
    db.commit()
    db.refresh(reg_code)
    msg = f"Registration code generated: {reg_code.code}"
    return templates.TemplateResponse("admin_approvals.html", {"request": request, "users": db.query(User).filter(User.is_approved == False).all(), "msg": msg})



@app.get("/unlock", response_class=HTMLResponse)
def unlock_get(request: Request):
    return templates.TemplateResponse("unlock.html", {"request": request})

@app.post("/unlock", response_class=HTMLResponse)
async def unlock_post(
    request: Request,
    rsa_token_id: str = Form(...),
    home_location: str = Form(...),
    ad_account_id: str = Form(...),
    question_1: str = Form(...),
    answer_1: str = Form(...),
    question_2: str = Form(...),
    answer_2: str = Form(...),
    question_3: str = Form(...),
    answer_3: str = Form(...),
    db: Session = Depends(get_db)
):

    try:
        user = db.query(User).filter(
            User.ad_account_id == ad_account_id,
            User.rsa_token_id == rsa_token_id,
            User.home_location == home_location,
            User.question_1 == question_1, User.answer_1 == hash_answer(answer_1),
            User.question_2 == question_2, User.answer_2 == hash_answer(answer_2),
            User.question_3 == question_3, User.answer_3 == hash_answer(answer_3)
        ).first()
        if user:
            # Check in Active Directory before unlock
            if not check_user_in_ad(ad_account_id):
                return templates.TemplateResponse("unlock.html", {"request": request, "msg": "User not found in Active Directory."})
            # Try to unlock in AD (expand as needed)
            try:
                from .ad_utils import unlock_ad_account
                unlock_ad_account(ad_account_id)
                logging.info(f"Unlocked AD account: {ad_account_id}")
                return templates.TemplateResponse("unlock.html", {"request": request, "msg": "Account unlocked successfully."})
            except Exception as e:
                logging.error(f"Failed to unlock AD account: {ad_account_id} - {e}")
                return templates.TemplateResponse("unlock.html", {"request": request, "msg": "Failed to unlock account in AD."})
        else:
            return templates.TemplateResponse("unlock.html", {"request": request, "msg": "User not found or answers incorrect. Please contact DevOps team."})
    except Exception as e:
        logging.warning(f"Unlock endpoint: Could not connect to DB: {e}")
        return templates.TemplateResponse("unlock.html", {"request": request, "msg": "Database unavailable. Please try again later."})
# Admin approval endpoints

@app.get("/admin/approvals", response_class=HTMLResponse)
def admin_approvals(request: Request, db: Session = Depends(get_db), auth: bool = Depends(verify_admin)):
    users = db.query(User).filter(User.is_approved == False).all()
    return templates.TemplateResponse("admin_approvals.html", {"request": request, "users": users})

@app.post("/admin/approve/{user_id}")
def approve_user(user_id: int, db: Session = Depends(get_db), auth: bool = Depends(verify_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.is_approved = True
        db.commit()
        logging.info(f"Admin approved user: {user_id}")
        audit_log(f"Admin approved user: {user_id}")
        # Notify user if email field exists (extend User model if needed)
    return RedirectResponse(url="/admin/approvals", status_code=status.HTTP_303_SEE_OTHER)



@app.get("/status", response_class=HTMLResponse)
def status_get(request: Request):
    return templates.TemplateResponse("status.html", {"request": request})

@app.post("/status", response_class=HTMLResponse)
async def status_post(
    request: Request,
    ad_account_id: str = Form(...),
    rsa_token_id: str = Form(...),
    home_location: str = Form(...),
    question_1: str = Form(...),
    answer_1: str = Form(...),
    question_2: str = Form(...),
    answer_2: str = Form(...),
    question_3: str = Form(...),
    answer_3: str = Form(...),
    db: Session = Depends(get_db)
):
    try:
        user = db.query(User).filter(
            User.ad_account_id == ad_account_id,
            User.rsa_token_id == rsa_token_id,
            User.home_location == home_location,
            User.question_1 == question_1, User.answer_1 == answer_1,
            User.question_2 == question_2, User.answer_2 == answer_2,
            User.question_3 == question_3, User.answer_3 == answer_3
        ).first()
        if user:
            return templates.TemplateResponse("status.html", {"request": request, "msg": "Account exists in the system."})
        else:
            return templates.TemplateResponse("status.html", {"request": request, "msg": "Account not found. Please check with the security team."})
    except Exception as e:
        logging.warning(f"Status endpoint: Could not connect to DB: {e}")
        return templates.TemplateResponse("status.html", {"request": request, "msg": "Database unavailable. Please try again later."})



@app.get("/create-user", response_class=HTMLResponse)
def create_user_get(request: Request):
    return templates.TemplateResponse("create_user.html", {"request": request})

@app.post("/create-user", response_class=HTMLResponse)
async def create_user_post(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    middle_name: str = Form(None),
    rsa_token_id: str = Form(...),
    home_location: str = Form(...),
    question_1: str = Form(...),
    answer_1: str = Form(...),
    question_2: str = Form(...),
    answer_2: str = Form(...),
    question_3: str = Form(...),
    answer_3: str = Form(...),
    db: Session = Depends(get_db)
):
    user = User(
        first_name=first_name,
        last_name=last_name,
        middle_name=middle_name,
        rsa_token_id=rsa_token_id,
        home_location=home_location,
        question_1=question_1,
        answer_1=answer_1,
        question_2=question_2,
        answer_2=answer_2,
        question_3=question_3,
        answer_3=answer_3,
        is_approved=False
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return templates.TemplateResponse("create_user.html", {"request": request, "msg": "User submitted for approval."})
