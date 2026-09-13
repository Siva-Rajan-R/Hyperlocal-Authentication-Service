import json
from contextvars import ContextVar
from typing import Optional

current_user_ctx = ContextVar("current_user_ctx", default={})

def get_activity_log_user_info(custom_user_info: Optional[dict] = None) -> dict:
    user_info = custom_user_info if (custom_user_info and isinstance(custom_user_info, dict)) else current_user_ctx.get()
    if not isinstance(user_info, dict):
        user_info = {}
    email = user_info.get("email", "")
    user_name = user_info.get("name") or user_info.get("user_name")
    
    if not user_name and email:
        user_name = email.split("@")[0]
        
    final_name = user_name or "System"
    role = user_info.get("role", "")
    
    if email and final_name != email and f"- {email}" not in final_name:
        final_name = f"{final_name} - {email}"
        
    return {
        "user_name": final_name,
        "user_email": email,
        "user_role": role
    }
