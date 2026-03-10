from fastapi import FastAPI, APIRouter, HTTPException, UploadFile, File, Depends, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import csv
import io
import jwt
import bcrypt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'delta-ai-academy-secret-key-2026')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Security
security = HTTPBearer()

# Default SMTP Configuration from env
DEFAULT_SMTP_CONFIG = {
    "smtp_server": os.environ.get('SMTP_SERVER', 'smtp.gmail.com'),
    "smtp_port": int(os.environ.get('SMTP_PORT', 465)),
    "smtp_username": os.environ.get('SMTP_USERNAME', ''),
    "smtp_password": os.environ.get('SMTP_PASSWORD', ''),
    "smtp_from_email": os.environ.get('SMTP_FROM_EMAIL', ''),
    "smtp_from_name": os.environ.get('SMTP_FROM_NAME', 'Delta AI Academy'),
}

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# Auth Models
class UserCreate(BaseModel):
    email: str
    password: str
    name: str = ""

class UserLogin(BaseModel):
    email: str
    password: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: str
    name: str = ""
    password_hash: str
    is_admin: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    is_admin: bool


# Auth Helper Functions
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

def create_token(user_id: str, email: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = decode_token(token)
    user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


# Define Models
class StatusCheck(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusCheckCreate(BaseModel):
    client_name: str

class EmailSendRequest(BaseModel):
    recipient_email: str
    subject: str
    template_id: Optional[str] = None
    custom_html: Optional[str] = None

class BulkEmailRequest(BaseModel):
    subject: str
    template_id: Optional[str] = None

class EmailLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    recipient_email: str
    subject: str
    status: str  # 'sent', 'failed', 'pending', 'delivered', 'bounced'
    error_message: Optional[str] = None
    sent_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    delivered_at: Optional[datetime] = None
    batch_id: Optional[str] = None
    template_id: Optional[str] = None

class EmailTemplate(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    subject: str
    html_content: str
    is_default: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class EmailTemplateCreate(BaseModel):
    name: str
    subject: str
    html_content: str
    is_default: bool = False

class EmailTemplateUpdate(BaseModel):
    name: Optional[str] = None
    subject: Optional[str] = None
    html_content: Optional[str] = None
    is_default: Optional[bool] = None

class BatchJob(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    batch_id: str
    subject: str
    template_id: Optional[str] = None
    status: str = "queued"          # queued | processing | completed | failed
    total: int = 0
    successful: int = 0
    failed: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SMTPConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    smtp_server: str
    smtp_port: int = 465
    smtp_username: str
    smtp_password: str
    smtp_from_email: str
    smtp_from_name: str = "Delta AI Academy"
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class SMTPConfigCreate(BaseModel):
    name: str
    smtp_server: str
    smtp_port: int = 465
    smtp_username: str
    smtp_password: str
    smtp_from_email: str
    smtp_from_name: str = "Delta AI Academy"
    is_active: bool = True


# Helper function to get active SMTP config
async def get_active_smtp_config():
    config = await db.smtp_configs.find_one({"is_active": True}, {"_id": 0})
    if config:
        return config
    return DEFAULT_SMTP_CONFIG


# Email sending function
async def send_email_smtp(recipient_email: str, subject: str, html_content: str) -> tuple:
    """Send email via SMTP with SSL/TLS or STARTTLS"""
    try:
        smtp_config = await get_active_smtp_config()
        
        # Create SSL context
        context = ssl.create_default_context()
        
        # Create message
        message = MIMEMultipart("alternative")
        message["Subject"] = subject
        message["From"] = f"{smtp_config.get('smtp_from_name', 'Delta AI Academy')} <{smtp_config.get('smtp_from_email', smtp_config.get('smtp_username'))}>"
        message["To"] = recipient_email
        
        # Plain text version (strip HTML)
        import re
        plain_text = re.sub('<[^<]+?>', '', html_content)
        
        part_text = MIMEText(plain_text, "plain", _charset="utf-8")
        part_html = MIMEText(html_content, "html", _charset="utf-8")
        
        message.attach(part_text)
        message.attach(part_html)
        
        smtp_port = smtp_config.get('smtp_port', 465)
        
        # Use SMTP_SSL for port 465, STARTTLS for port 587
        if smtp_port == 465:
            with smtplib.SMTP_SSL(
                smtp_config.get('smtp_server'),
                smtp_port,
                context=context,
                timeout=30
            ) as server:
                server.login(smtp_config.get('smtp_username'), smtp_config.get('smtp_password'))
                server.sendmail(smtp_config.get('smtp_from_email', smtp_config.get('smtp_username')), [recipient_email], message.as_string())
        else:
            # Port 587 or others use STARTTLS
            with smtplib.SMTP(
                smtp_config.get('smtp_server'),
                smtp_port,
                timeout=30
            ) as server:
                server.starttls(context=context)
                server.login(smtp_config.get('smtp_username'), smtp_config.get('smtp_password'))
                server.sendmail(smtp_config.get('smtp_from_email', smtp_config.get('smtp_username')), [recipient_email], message.as_string())
        
        logger.info(f"Email sent successfully to {recipient_email}")
        return True, None
        
    except smtplib.SMTPAuthenticationError as e:
        error_msg = f"Authentication failed: {str(e)}"
        logger.error(error_msg)
        return False, error_msg
    except smtplib.SMTPException as e:
        error_msg = f"SMTP error: {str(e)}"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


# Default template
DEFAULT_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="margin:0; padding:0; background-color:#0a0a0a; font-family:Arial, Helvetica, sans-serif;">
<table width="100%" bgcolor="#0a0a0a" cellpadding="0" cellspacing="0">
<tr>
<td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#111111; margin:40px 0; border-radius:8px; overflow:hidden; border: 1px solid #222;">
<tr>
<td align="center" style="background:#111111; padding:30px 20px; border-bottom: 1px solid #222;">
<img src="https://customer-assets.emergentagent.com/job_mail-dispatch-18/artifacts/bs8dk0ju_IMG_5169.PNG" 
     alt="Delta AI Academy" 
     width="200" 
     style="display:block; margin-bottom:10px;">
</td>
</tr>
<tr>
<td style="padding:40px 30px; color:#e0e0e0; font-size:15px; line-height:1.7;">
<p style="margin-top:0; color:#ffffff;">Dear Valued Member,</p>
<p>This is a message from Delta AI Academy.</p>
<p>Thank you for being part of our community.</p>
<p style="margin-bottom:0;">
Best Regards,<br>
<strong style="color:#00d4aa;">Delta AI Academy Team</strong>
</p>
</td>
</tr>
<tr>
<td style="border-top:1px solid #222;"></td>
</tr>
<tr>
<td align="center" style="padding:25px 20px; font-size:12px; color:#666666;">
<p style="margin:0 0 10px 0;">© 2026 Delta AI Academy. All Rights Reserved.</p>
</td>
</tr>
</table>
</td>
</tr>
</table>
</body>
</html>'''


# Routes
@api_router.get("/")
async def root():
    return {"message": "Delta AI Academy Email Delivery System"}


# Auth Routes
@api_router.post("/auth/register")
async def register(user_data: UserCreate):
    """Register a new user"""
    # Check if user exists
    existing = await db.users.find_one({"email": user_data.email.lower()})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user = User(
        email=user_data.email.lower(),
        name=user_data.name,
        password_hash=hash_password(user_data.password)
    )
    
    doc = user.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.users.insert_one(doc)
    
    # Generate token
    token = create_token(user.id, user.email)
    
    return {
        "success": True,
        "token": token,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "is_admin": user.is_admin
        }
    }

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    """Login user"""
    user = await db.users.find_one({"email": credentials.email.lower()}, {"_id": 0})
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not verify_password(credentials.password, user['password_hash']):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    # Generate token
    token = create_token(user['id'], user['email'])
    
    return {
        "success": True,
        "token": token,
        "user": {
            "id": user['id'],
            "email": user['email'],
            "name": user.get('name', ''),
            "is_admin": user.get('is_admin', False)
        }
    }

@api_router.get("/auth/me")
async def get_me(current_user: dict = Depends(get_current_user)):
    """Get current user info"""
    return {
        "id": current_user['id'],
        "email": current_user['email'],
        "name": current_user.get('name', ''),
        "is_admin": current_user.get('is_admin', False)
    }


@api_router.post("/status", response_model=StatusCheck)
async def create_status_check(input: StatusCheckCreate):
    status_dict = input.model_dump()
    status_obj = StatusCheck(**status_dict)
    doc = status_obj.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    _ = await db.status_checks.insert_one(doc)
    return status_obj

@api_router.get("/status", response_model=List[StatusCheck])
async def get_status_checks():
    status_checks = await db.status_checks.find({}, {"_id": 0}).to_list(1000)
    for check in status_checks:
        if isinstance(check['timestamp'], str):
            check['timestamp'] = datetime.fromisoformat(check['timestamp'])
    return status_checks


# SMTP Configuration Routes
@api_router.get("/smtp/configs")
async def get_smtp_configs():
    """Get all SMTP configurations"""
    configs = await db.smtp_configs.find({}, {"_id": 0}).to_list(100)
    # Mask passwords
    for config in configs:
        if config.get('smtp_password'):
            config['smtp_password'] = '********'
    return {"configs": configs}

@api_router.post("/smtp/configs")
async def create_smtp_config(config: SMTPConfigCreate):
    """Create a new SMTP configuration"""
    # If this is set as active, deactivate others
    if config.is_active:
        await db.smtp_configs.update_many({}, {"$set": {"is_active": False}})
    
    config_obj = SMTPConfig(**config.model_dump())
    doc = config_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.smtp_configs.insert_one(doc)
    
    return {"success": True, "message": "SMTP configuration created", "id": config_obj.id}

@api_router.put("/smtp/configs/{config_id}")
async def update_smtp_config(config_id: str, updates: dict):
    """Update an SMTP configuration"""
    # If setting as active, deactivate others
    if updates.get('is_active'):
        await db.smtp_configs.update_many({}, {"$set": {"is_active": False}})
    
    result = await db.smtp_configs.update_one(
        {"id": config_id},
        {"$set": updates}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Configuration not found")
    
    return {"success": True, "message": "SMTP configuration updated"}

@api_router.delete("/smtp/configs/{config_id}")
async def delete_smtp_config(config_id: str):
    """Delete an SMTP configuration"""
    result = await db.smtp_configs.delete_one({"id": config_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Configuration not found")
    return {"success": True, "message": "SMTP configuration deleted"}

@api_router.post("/smtp/test")
async def test_smtp_config(config: SMTPConfigCreate):
    """Test SMTP configuration"""
    try:
        context = ssl.create_default_context()
        if config.smtp_port == 465:
            with smtplib.SMTP_SSL(config.smtp_server, config.smtp_port, context=context, timeout=10) as server:
                server.login(config.smtp_username, config.smtp_password)
        else:
            with smtplib.SMTP(config.smtp_server, config.smtp_port, timeout=10) as server:
                server.starttls(context=context)
                server.login(config.smtp_username, config.smtp_password)
        return {"success": True, "message": "SMTP connection successful"}
    except Exception as e:
        return {"success": False, "message": str(e)}


# Email Template Routes
@api_router.get("/templates")
async def get_templates():
    """Get all email templates"""
    templates = await db.email_templates.find({}, {"_id": 0}).to_list(100)
    
    # Add default template if none exist
    if not templates:
        default = EmailTemplate(
            name="Default Template",
            subject="Message from Delta AI Academy",
            html_content=DEFAULT_TEMPLATE,
            is_default=True
        )
        doc = default.model_dump()
        doc['created_at'] = doc['created_at'].isoformat()
        doc['updated_at'] = doc['updated_at'].isoformat()
        await db.email_templates.insert_one(doc)
        templates = [doc]
    
    return {"templates": templates}

@api_router.get("/templates/{template_id}")
async def get_template(template_id: str):
    """Get a specific template"""
    template = await db.email_templates.find_one({"id": template_id}, {"_id": 0})
    if not template:
        raise HTTPException(status_code=404, detail="Template not found")
    return template

@api_router.post("/templates")
async def create_template(template: EmailTemplateCreate):
    """Create a new email template"""
    # If this is set as default, unset others
    if template.is_default:
        await db.email_templates.update_many({}, {"$set": {"is_default": False}})
    
    template_obj = EmailTemplate(**template.model_dump())
    doc = template_obj.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    await db.email_templates.insert_one(doc)
    
    return {"success": True, "message": "Template created", "id": template_obj.id}

@api_router.put("/templates/{template_id}")
async def update_template(template_id: str, updates: EmailTemplateUpdate):
    """Update an email template"""
    update_data = {k: v for k, v in updates.model_dump().items() if v is not None}
    
    if not update_data:
        raise HTTPException(status_code=400, detail="No updates provided")
    
    # If setting as default, unset others
    if update_data.get('is_default'):
        await db.email_templates.update_many({}, {"$set": {"is_default": False}})
    
    update_data['updated_at'] = datetime.now(timezone.utc).isoformat()
    
    result = await db.email_templates.update_one(
        {"id": template_id},
        {"$set": update_data}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Template not found")
    
    return {"success": True, "message": "Template updated"}

@api_router.delete("/templates/{template_id}")
async def delete_template(template_id: str):
    """Delete an email template"""
    result = await db.email_templates.delete_one({"id": template_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Template not found")
    return {"success": True, "message": "Template deleted"}


# Email Routes
@api_router.post("/email/send")
async def send_single_email(request: EmailSendRequest):
    """Send a single email"""
    # Get template if specified
    html_content = request.custom_html or DEFAULT_TEMPLATE
    if request.template_id:
        template = await db.email_templates.find_one({"id": request.template_id}, {"_id": 0})
        if template:
            html_content = template.get('html_content', DEFAULT_TEMPLATE)
    
    success, error = await send_email_smtp(request.recipient_email, request.subject, html_content)
    
    # Log the email
    log_entry = EmailLog(
        recipient_email=request.recipient_email,
        subject=request.subject,
        status='sent' if success else 'failed',
        error_message=error,
        template_id=request.template_id
    )
    doc = log_entry.model_dump()
    doc['sent_at'] = doc['sent_at'].isoformat()
    if doc.get('delivered_at'):
        doc['delivered_at'] = doc['delivered_at'].isoformat()
    await db.email_logs.insert_one(doc)
    
    if success:
        return {"success": True, "message": f"Email sent to {request.recipient_email}", "log_id": log_entry.id}
    else:
        raise HTTPException(status_code=500, detail=error)


async def process_bulk_emails_background(batch_id: str, emails: list, subject: str, html_content: str, template_id: Optional[str]):
    """Background worker: sends emails one by one and updates batch progress in DB."""
    await db.batch_jobs.update_one(
        {"batch_id": batch_id},
        {"$set": {"status": "processing", "updated_at": datetime.now(timezone.utc).isoformat()}}
    )

    for email in emails:
        try:
            success, error = await send_email_smtp(email, subject, html_content)

            log_entry = EmailLog(
                recipient_email=email,
                subject=subject,
                status='sent' if success else 'failed',
                error_message=error,
                batch_id=batch_id,
                template_id=template_id
            )
            doc = log_entry.model_dump()
            doc['sent_at'] = doc['sent_at'].isoformat()
            if doc.get('delivered_at'):
                doc['delivered_at'] = doc['delivered_at'].isoformat()
            await db.email_logs.insert_one(doc)

            if success:
                await db.batch_jobs.update_one(
                    {"batch_id": batch_id},
                    {"$inc": {"successful": 1}, "$set": {"updated_at": datetime.now(timezone.utc).isoformat()}}
                )
            else:
                await db.batch_jobs.update_one(
                    {"batch_id": batch_id},
                    {"$inc": {"failed": 1}, "$set": {"updated_at": datetime.now(timezone.utc).isoformat()}}
                )
        except Exception as e:
            logger.error(f"Unexpected error processing email {email} in batch {batch_id}: {str(e)}")
            await db.batch_jobs.update_one(
                {"batch_id": batch_id},
                {"$inc": {"failed": 1}, "$set": {"updated_at": datetime.now(timezone.utc).isoformat()}}
            )

    await db.batch_jobs.update_one(
        {"batch_id": batch_id},
        {"$set": {"status": "completed", "updated_at": datetime.now(timezone.utc).isoformat()}}
    )
    logger.info(f"Batch {batch_id} completed.")


@api_router.post("/email/bulk")
async def send_bulk_emails(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    subject: str = "Message from Delta AI Academy",
    template_id: Optional[str] = None
):
    """Queue a bulk email job. Returns immediately with a batch_id to track progress."""
    if not file.filename.endswith('.csv'):
        raise HTTPException(status_code=400, detail="Please upload a CSV file")

    content = await file.read()
    decoded = content.decode('utf-8')

    # Get template
    html_content = DEFAULT_TEMPLATE
    if template_id:
        template = await db.email_templates.find_one({"id": template_id}, {"_id": 0})
        if template:
            html_content = template.get('html_content', DEFAULT_TEMPLATE)

    # Parse CSV - handle both with and without headers
    lines = decoded.strip().split('\n')
    first_line = lines[0].strip().lower() if lines else ''

    emails = []

    if first_line in ['email', 'emails', 'e-mail', 'email_address', 'emailaddress']:
        reader = csv.DictReader(io.StringIO(decoded))
        for row in reader:
            email = row.get('email', row.get('Email', row.get('EMAIL', ''))).strip()
            if email and '@' in email:
                emails.append(email)
    elif ',' in first_line and 'email' in first_line:
        reader = csv.DictReader(io.StringIO(decoded))
        for row in reader:
            email = row.get('email', row.get('Email', row.get('EMAIL', ''))).strip()
            if email and '@' in email:
                emails.append(email)
    else:
        for line in lines:
            email = line.strip()
            if ',' in email:
                email = email.split(',')[0].strip()
            if email and '@' in email:
                emails.append(email)

    if not emails:
        raise HTTPException(status_code=400, detail="No valid email addresses found in the CSV file")

    # Create batch job record in DB
    batch_id = str(uuid.uuid4())
    batch_job = BatchJob(
        batch_id=batch_id,
        subject=subject,
        template_id=template_id,
        status="queued",
        total=len(emails)
    )
    doc = batch_job.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    doc['updated_at'] = doc['updated_at'].isoformat()
    await db.batch_jobs.insert_one(doc)

    # Fire background task — response is returned before emails start sending
    background_tasks.add_task(
        process_bulk_emails_background,
        batch_id, emails, subject, html_content, template_id
    )

    return {
        "success": True,
        "batch_id": batch_id,
        "status": "queued",
        "total_emails": len(emails),
        "message": f"Bulk email job queued for {len(emails)} recipients. Use GET /api/email/bulk/{batch_id}/status to track progress."
    }


@api_router.get("/email/bulk/{batch_id}/status")
async def get_bulk_email_status(batch_id: str):
    """Poll the live progress of a bulk email batch job."""
    job = await db.batch_jobs.find_one({"batch_id": batch_id}, {"_id": 0})
    if not job:
        raise HTTPException(status_code=404, detail="Batch job not found")

    total = job.get("total", 0)
    successful = job.get("successful", 0)
    failed = job.get("failed", 0)
    processed = successful + failed
    progress_pct = round((processed / total) * 100, 1) if total > 0 else 0

    return {
        "batch_id": batch_id,
        "status": job.get("status"),          # queued | processing | completed | failed
        "total": total,
        "processed": processed,
        "successful": successful,
        "failed": failed,
        "progress_percent": progress_pct,
        "subject": job.get("subject"),
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
    }


@api_router.get("/email/logs")
async def get_email_logs(limit: int = 100, skip: int = 0, status: Optional[str] = None):
    """Get email logs with optional status filter"""
    query = {}
    if status:
        query["status"] = status
    
    logs = await db.email_logs.find(query, {"_id": 0}).sort("sent_at", -1).skip(skip).limit(limit).to_list(limit)
    total = await db.email_logs.count_documents(query)
    
    return {
        "logs": logs,
        "total": total,
        "limit": limit,
        "skip": skip
    }


@api_router.get("/email/stats")
async def get_email_stats():
    """Get email statistics"""
    total_sent = await db.email_logs.count_documents({"status": "sent"})
    total_failed = await db.email_logs.count_documents({"status": "failed"})
    total_pending = await db.email_logs.count_documents({"status": "pending"})
    total_delivered = await db.email_logs.count_documents({"status": "delivered"})
    total_bounced = await db.email_logs.count_documents({"status": "bounced"})
    
    recent = await db.email_logs.find({}, {"_id": 0}).sort("sent_at", -1).limit(5).to_list(5)
    
    return {
        "total_sent": total_sent,
        "total_failed": total_failed,
        "total_pending": total_pending,
        "total_delivered": total_delivered,
        "total_bounced": total_bounced,
        "recent_emails": recent
    }


@api_router.put("/email/logs/{log_id}/status")
async def update_email_status(log_id: str, status: str):
    """Update delivery status of an email"""
    valid_statuses = ['sent', 'failed', 'pending', 'delivered', 'bounced']
    if status not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {valid_statuses}")
    
    update_data = {"status": status}
    if status == 'delivered':
        update_data['delivered_at'] = datetime.now(timezone.utc).isoformat()
    
    result = await db.email_logs.update_one(
        {"id": log_id},
        {"$set": update_data}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Email log not found")
    
    return {"success": True, "message": f"Status updated to {status}"}


@api_router.get("/email/template")
async def get_default_template():
    """Get the default email template (legacy endpoint)"""
    template = await db.email_templates.find_one({"is_default": True}, {"_id": 0})
    if not template:
        return {
            "template_name": "Default Template",
            "html": DEFAULT_TEMPLATE,
            "subject": "Message from Delta AI Academy"
        }
    return {
        "template_name": template.get('name'),
        "html": template.get('html_content'),
        "subject": template.get('subject')
    }


# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
