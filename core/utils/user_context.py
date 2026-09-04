import json
from contextvars import ContextVar
from typing import Optional

current_user_ctx = ContextVar("current_user_ctx", default={})

def get_activity_log_user_info() -> dict:
    user_info = current_user_ctx.get()
    email = user_info.get("email", "")
    user_name = user_info.get("name") or user_info.get("user_name")
    
    if not user_name and email:
        user_name = email.split("@")[0]
        
    final_name = user_name or "System"
    role = user_info.get("role", "")
    
    if email:
        final_name = f"{final_name} - {email}"
        
    return {
        "user_name": final_name,
        "user_email": email,
        "user_role": role
    }


