# app.py
import os
import re
import io
import sys
import base64
from datetime import datetime
from uuid import uuid4

import streamlit as st
from supabase import create_client
import pandas as pd
from PIL import Image

# ----------------------------
# Read secrets from Streamlit (or .streamlit/secrets.toml)
# ----------------------------
try:
    SUPABASE_URL = st.secrets["SUPABASE_URL"]
    SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
    BUCKET_NAME = st.secrets.get("SUPABASE_BUCKET", "id_uploads")
    ADMIN_KEY = st.secrets.get("ADMIN_KEY", "")
except Exception:
    st.error("Supabase secrets not found. Add SUPABASE_URL and SUPABASE_KEY in Streamlit Secrets.")
    st.stop()

# Create Supabase client
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

# ----------------------------
# Helpers
# ----------------------------
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def is_valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))


def _parse_supabase_response(res):
    """
    Normalize many supabase client response shapes into (ok: bool, data, error_message).
    Handles:
     - plain strings (public URLs returned as str)
     - objects with .data/.error
     - objects with .user/.session/.access_token (AuthResponse-like)
     - objects with .status_code/.json()
     - plain dicts
    """
    try:
        # None
        if res is None:
            return False, None, "No response (None)"

        # If res is a plain string (some SDKs return the public URL as a str)
        if isinstance(res, str):
            return True, res, None

        # If already a plain dict
        if isinstance(res, dict):
            data = res.get("data") or res.get("body") or None
            error = res.get("error") or res.get("message") or None
            status = res.get("status_code") or res.get("status")
            ok = True
            if status:
                try:
                    ok = 200 <= int(status) < 300
                except Exception:
                    ok = False
            else:
                ok = error is None
            return ok, data, error

        # If object has .data or .error attributes (common)
        if hasattr(res, "data") or hasattr(res, "error"):
            data = getattr(res, "data", None)
            error = getattr(res, "error", None)
            ok = (error is None)
            return ok, data, error

        # If object looks like an AuthResponse (has user/session/access_token)
        if hasattr(res, "user") or hasattr(res, "session") or hasattr(res, "access_token") or hasattr(res, "refresh_token"):
            payload = {}
            try:
                if hasattr(res, "user"):
                    payload["user"] = getattr(res, "user")
                if hasattr(res, "session"):
                    payload["session"] = getattr(res, "session")
                else:
                    sess = {}
                    if hasattr(res, "access_token"):
                        sess["access_token"] = getattr(res, "access_token")
                    if hasattr(res, "refresh_token"):
                        sess["refresh_token"] = getattr(res, "refresh_token")
                    if hasattr(res, "expires_in"):
                        sess["expires_in"] = getattr(res, "expires_in")
                    if sess:
                        payload["session"] = sess
            except Exception:
                pass
            ok = bool(payload.get("user") or payload.get("session"))
            err = None
            if hasattr(res, "error"):
                err = getattr(res, "error")
            if hasattr(res, "message") and not err:
                err = getattr(res, "message")
            return ok, payload or None, err

        # If object has status_code / data / json (http-like)
        if hasattr(res, "status_code"):
            status = getattr(res, "status_code", None)
            data = None
            error = None
            if hasattr(res, "data"):
                data = getattr(res, "data")
            elif callable(getattr(res, "json", None)):
                try:
                    payload = res.json()
                    if isinstance(payload, dict):
                        data = payload.get("data", payload)
                        error = payload.get("error") or payload.get("message")
                    else:
                        data = payload
                except Exception:
                    data = None
            ok = True
            if status is not None:
                try:
                    ok = 200 <= int(status) < 300
                except Exception:
                    ok = False
            if not ok and error is None:
                error = f"HTTP {status}"
            return ok, data, error

        # Fallback: unknown type
        return False, None, f"Unexpected response type: {type(res).__name__}"
    except Exception as exc:
        return False, None, f"Exception while parsing response: {exc}"


def check_user_exists(email: str):
    """
    Return (exists: bool, reason: str).
    Checks users table and common auth endpoints.
    """
    # 1) Check users table first
    try:
        tbl_res = supabase.table("users").select("email").eq("email", email).limit(1).execute()
        ok, data, err = _parse_supabase_response(tbl_res)
        if ok:
            users = data or []
            if isinstance(users, dict) and "data" in users:
                users = users.get("data") or []
            if isinstance(users, list) and len(users) > 0:
                return True, "Found in users table"
    except Exception:
        pass

    # 2) Try common auth lookups
    try:
        try:
            auth_res = supabase.auth.api.get_user_by_email(email)
            ok, data, err = _parse_supabase_response(auth_res)
            if ok and data:
                return True, "Found in Supabase Auth (api.get_user_by_email)"
        except Exception:
            pass

        try:
            auth_res = supabase.auth.admin.get_user_by_email(email)
            ok, data, err = _parse_supabase_response(auth_res)
            if ok and data:
                return True, "Found in Supabase Auth (auth.admin.get_user_by_email)"
        except Exception:
            pass

        try:
            auth_res = supabase.auth.get_user_by_email(email)
            ok, data, err = _parse_supabase_response(auth_res)
            if ok and data:
                return True, "Found in Supabase Auth (auth.get_user_by_email)"
        except Exception:
            pass

        try:
            users_list = supabase.auth.list_users()
            ok, data, err = _parse_supabase_response(users_list)
            if ok and isinstance(data, dict) and "users" in data:
                for u in data["users"]:
                    if u.get("email") == email:
                        return True, "Found in Supabase Auth (list_users)"
        except Exception:
            pass

    except Exception:
        pass

    return False, "Not found"


def create_auth_user(email: str, password: str):
    """
    Create a Supabase Auth user using sign_up.
    Returns (ok: bool, payload_or_error).
    """
    attempts = []
    # Attempt 1: dict-style
    try:
        res = supabase.auth.sign_up({"email": email, "password": password})
        ok, data, err = _parse_supabase_response(res)
        if ok:
            return True, data
        attempts.append(("dict-style", err or data))
    except Exception as e:
        attempts.append(("dict-style-exception", str(e)))

    # Attempt 2: positional args (some clients)
    try:
        if hasattr(supabase.auth, "sign_up") and callable(supabase.auth.sign_up):
            res = supabase.auth.sign_up(email, password)
            ok, data, err = _parse_supabase_response(res)
            if ok:
                return True, data
            attempts.append(("positional", err or data))
    except Exception as e:
        attempts.append(("positional-exception", str(e)))

    # Attempt 3: single-dict (email-only)
    try:
        res = supabase.auth.sign_up({"email": email})
        ok, data, err = _parse_supabase_response(res)
        if ok:
            return True, data
        attempts.append(("dict-email-only", err or data))
    except Exception as e:
        attempts.append(("dict-email-only-exception", str(e)))

    # Try to extract user/session if last res had those attributes
    try:
        if 'res' in locals() and (hasattr(res, "user") or hasattr(res, "session")):
            payload = {}
            user_obj = getattr(res, "user", None)
            if user_obj is not None:
                if isinstance(user_obj, dict):
                    payload["user"] = user_obj
                else:
                    try:
                        user_dict = {}
                        for attr in ("id", "email", "aud", "role"):
                            if hasattr(user_obj, attr):
                                user_dict[attr] = getattr(user_obj, attr)
                        payload["user"] = user_dict if user_dict else str(user_obj)
                    except Exception:
                        payload["user"] = str(user_obj)
            session_obj = getattr(res, "session", None)
            if session_obj is not None:
                if isinstance(session_obj, dict):
                    payload["session"] = session_obj
                else:
                    try:
                        sess = {}
                        for attr in ("access_token", "expires_at", "refresh_token"):
                            if hasattr(session_obj, attr):
                                sess[attr] = getattr(session_obj, attr)
                        payload["session"] = sess if sess else str(session_obj)
                    except Exception:
                        payload["session"] = str(session_obj)
            if payload:
                return True, payload
    except Exception:
        pass

    attempt_text = "; ".join([f"{k}: {v}" for k, v in attempts])
    return False, f"All sign_up attempts failed. Attempts: {attempt_text}"


def sign_in_user(email: str, password: str):
    """
    Robust sign-in wrapper. Returns (ok: bool, payload_or_error_str).
    Handles modern sign_in_with_password and AuthResponse shapes.
    """
    attempts = []

    def _parse_and_return(res, label):
        ok, data, err = _parse_supabase_response(res)
        # debug dump when enabled
        if st.secrets.get("DEBUG", "") == "1":
            st.write(f"DEBUG sign-in raw ({label}):", repr(res))
            st.write("DEBUG parsed:", ok, data, err)
        if ok:
            # If data is a dict containing user/session, return it
            if isinstance(data, dict) and ("user" in data or "session" in data):
                return True, data
            # If res itself contains user/session attributes, parse again (best-effort)
            try:
                payload = {}
                if hasattr(res, "user"):
                    payload["user"] = getattr(res, "user")
                if hasattr(res, "session"):
                    payload["session"] = getattr(res, "session")
                if payload:
                    return True, payload
            except Exception:
                pass
            # Otherwise return whatever parsed as success
            return True, data or "Signed in (no user/session payload found)"
        else:
            # If err present, return it; otherwise give a default
            return False, str(err) if err else f"Sign-in failed ({label}) - no error message."

    # 1) Preferred: sign_in_with_password
    try:
        if hasattr(supabase.auth, "sign_in_with_password"):
            res = supabase.auth.sign_in_with_password({"email": email, "password": password})
            ok, out = _parse_and_return(res, "sign_in_with_password")
            if ok:
                return True, out
            attempts.append(("sign_in_with_password", out))
        else:
            attempts.append(("sign_in_with_password-missing", "method not available"))
    except Exception as e:
        attempts.append(("sign_in_with_password-exception", str(e)))

    # 2) Fallback older shapes
    try:
        if hasattr(supabase.auth, "sign_in"):
            try:
                res = supabase.auth.sign_in({"email": email, "password": password})
                ok, out = _parse_and_return(res, "sign_in-dict")
                if ok:
                    return True, out
                attempts.append(("sign_in-dict", out))
            except Exception as e:
                attempts.append(("sign_in-dict-ex", str(e)))
        else:
            attempts.append(("sign_in-dict-missing", "method not available"))
    except Exception as e:
        attempts.append(("sign_in-dict-ex2", str(e)))

    # final guidance: inspect existence and confirmation status
    exists, reason = False, "unknown"
    try:
        exists, reason = check_user_exists(email)
    except Exception:
        exists, reason = False, "check_user_exists failed"

    # Try to see if email is unconfirmed (best-effort)
    email_confirmed = None
    try:
        auth_user = None
        try:
            auth_user = supabase.auth.api.get_user_by_email(email)
        except Exception:
            pass
        if not auth_user:
            try:
                auth_user = supabase.auth.admin.get_user_by_email(email)
            except Exception:
                pass
        ok2, data2, err2 = _parse_supabase_response(auth_user) if auth_user is not None else (False, None, None)
        if ok2 and data2:
            u = None
            if isinstance(data2, dict):
                if data2.get("email"):
                    u = data2
                elif "user" in data2 and isinstance(data2["user"], dict):
                    u = data2["user"]
            if isinstance(u, dict):
                email_confirmed = bool(u.get("email_confirmed_at") or u.get("confirmed_at") or u.get("email_confirmed") or u.get("confirmed"))
    except Exception:
        email_confirmed = None

    # Compose final friendly message
    msg_parts = []
    msg_parts.append("Unable to sign in. Reason(s):")
    for k, v in attempts:
        msg_parts.append(f"- {k}: {v}")

    if exists:
        if email_confirmed is False:
            msg_parts.append("- Your account exists but the email appears not confirmed. Check your inbox for the confirmation email or use 'Resend confirmation'.")
        else:
            msg_parts.append("- The email exists. The password may be incorrect. Try resetting your password (Forgot password).")
            msg_parts.append("  Reset via Supabase Dashboard (Auth → Users → Reset password) or use the app's reset flow.")
    else:
        msg_parts.append("- No account found for that email. Create a new account or verify the signup email.")

    msg_parts.append("If you're testing, enable DEBUG in Streamlit secrets (DEBUG=\"1\") to see the raw auth response.")
    final_msg = "\n".join(msg_parts)
    return False, final_msg


# ----------------------------
# Password reset & resend confirmation helpers
# ----------------------------
def _try_calls(calls):
    """Utility: try callables in order, parse result with _parse_supabase_response."""
    attempts = []
    for name, fn in calls:
        try:
            res = fn()
            ok, data, err = _parse_supabase_response(res)
            if ok:
                return True, f"Success ({name})", data
            attempts.append((name, err or data))
        except Exception as e:
            attempts.append((name, str(e)))
    return False, f"All attempts failed: {attempts}", None


def send_password_reset(email: str):
    """
    Try to trigger Supabase password reset email using several client shapes.
    Returns (ok: bool, msg: str).
    """
    calls = []
    # Common shapes
    calls.append(("auth.api.reset_password_for_email", lambda: supabase.auth.api.reset_password_for_email(email)))
    calls.append(("auth.reset_password_for_email", lambda: supabase.auth.reset_password_for_email(email)))
    calls.append(("auth.send_reset_password_email", lambda: supabase.auth.send_reset_password_email(email)))
    calls.append(("auth.admin.reset_user_password", lambda: supabase.auth.admin.reset_user_password(email)))
    calls.append(("rpc.reset_password", lambda: supabase.rpc("reset_password", {"email": email})))
    ok, msg, data = _try_calls(calls)
    if ok:
        return True, "Password reset requested — check your email for instructions."
    return False, f"Could not request password reset. {msg}"


def resend_confirmation(email: str):
    """
    Try to resend confirmation email via common admin/api shapes.
    Returns (ok: bool, msg: str).
    """
    calls = []
    calls.append(("auth.api.generate_confirmation", lambda: supabase.auth.api.generate_confirmation(email)))
    calls.append(("auth.api.send_user_confirmation", lambda: supabase.auth.api.send_user_confirmation(email)))
    calls.append(("auth.admin.generate_link", lambda: supabase.auth.admin.generate_link('confirm', email)))
    calls.append(("auth.send_confirmation_email", lambda: supabase.auth.send_confirmation_email(email)))
    ok, msg, data = _try_calls(calls)
    if ok:
        return True, "Confirmation email resent — check your inbox (and spam)."
    return False, f"Could not resend confirmation. {msg}"


# ----------------------------
# Upload helpers (robust)
# ----------------------------
def upload_id_image_to_storage(uploaded_file, path: str):
    """
    Upload id image and return (ok, public_url_or_error_str).
    """
    attempts = []
    try:
        file_bytes = uploaded_file.getvalue()
    except Exception as e:
        return False, f"Could not read uploaded file bytes: {e}"

    upload_calls = [
        (lambda: supabase.storage.from_(BUCKET_NAME).upload(path, file_bytes), "bytes"),
        (lambda: supabase.storage.from_(BUCKET_NAME).upload(path, io.BytesIO(file_bytes)), "file-like"),
    ]

    last_res = None
    for call_fn, desc in upload_calls:
        try:
            res = call_fn()
            last_res = res

            # If upload response contains path info, try to extract it
            try:
                ok, data, err = _parse_supabase_response(res)
            except Exception:
                ok, data, err = False, None, "Could not parse upload response"

            # If upload returned dict with path or key, use it to get public url
            p = None
            if ok and isinstance(data, dict):
                p = data.get("path") or data.get("full_path") or data.get("fullPath") or data.get("key")
            # Some SDKs return strings/objects we can't parse - we still try to use the requested path param
            if not p:
                # try to compute path from known pattern where res.path/full_path exist
                try:
                    if hasattr(res, "path") and getattr(res, "path"):
                        p = getattr(res, "path")
                    elif hasattr(res, "full_path") and getattr(res, "full_path"):
                        p = getattr(res, "full_path")
                except Exception:
                    p = None

            # If we have a path inside bucket, ensure it's the key (no bucket prefix)
            if p:
                if isinstance(p, str):
                    prefix = f"{BUCKET_NAME}/"
                    if p.startswith(prefix):
                        p = p[len(prefix):]

                try:
                    url_res = supabase.storage.from_(BUCKET_NAME).get_public_url(p)
                    oku, datu, erru = _parse_supabase_response(url_res)
                    if oku:
                        # datu may be dict or str
                        if isinstance(datu, dict):
                            return True, datu.get("publicUrl") or datu.get("publicURL") or datu.get("public_url") or str(datu)
                        return True, str(datu)
                    else:
                        # upload succeeded but could not obtain public URL
                        return True, f"Upload succeeded; could not obtain public URL: {erru or datu}"
                except Exception as e:
                    return True, f"Upload succeeded; exception obtaining public URL: {e}"

            # Last resort: if parser says ok and data was present but no path, return a textual success
            if ok:
                return True, f"Upload seemed to succeed. Response: {data}"

        except Exception as e:
            attempts.append((desc, f"exception: {e}"))
            continue

    debug_last = ""
    try:
        if last_res is not None:
            debug_last = repr(last_res)
    except Exception:
        debug_last = "<could not repr last_res>"

    attempt_text = "; ".join([f"{k}: {v}" for k, v in attempts])
    error_msg = f"Upload failed. Attempts: {attempt_text}. Last response repr: {debug_last}"
    return False, error_msg


def save_metadata_to_table(email: str, auth_user_id: str, is_adult: bool, image_path: str, image_url: str):
    payload = {
        "email": email,
        "auth_user_id": auth_user_id,
        "is_adult": is_adult,
        "id_image_path": image_path,
        "id_image_public_url": image_url,
        "created_at": datetime.utcnow().isoformat(),
    }
    try:
        res = supabase.table("users").insert(payload).execute()
    except Exception as e:
        return False, f"Exception inserting metadata: {e}"

    ok, data, err = _parse_supabase_response(res)
    if ok:
        return True, data
    else:
        return False, err


# ----------------------------
# Session state init
# ----------------------------
if "logged_in" not in st.session_state:
    st.session_state["logged_in"] = False
if "user_email" not in st.session_state:
    st.session_state["user_email"] = None
if "message" not in st.session_state:
    st.session_state["message"] = ""
if "course_images" not in st.session_state:
    st.session_state["course_images"] = {}  # course_id -> public_url


def do_logout():
    st.session_state["logged_in"] = False
    st.session_state["user_email"] = None
    st.session_state["message"] = "You have logged out."
    go_to_page("signup")


# ----------------------------
# Page routing helpers (query param based) with defensive rerun
# ----------------------------
def current_page():
    params = st.experimental_get_query_params()
    page = params.get("page", ["signup"])[0]
    return page


def go_to_page(page_name: str):
    """
    Navigate using query params and request a rerun.
    Safe if the file is executed directly (falls back to sys.exit).
    """
    try:
        st.experimental_set_query_params(page=page_name)
    except Exception:
        # ignore if running older streamlit or outside of streamlit
        pass

    try:
        st.experimental_rerun()
    except Exception as exc:
        print(f"Requested rerun for page={page_name} (fallback exit): {exc}")
        sys.exit(0)


# ----------------------------
# UI / Theme + Sidebar + Hero
# ----------------------------
st.set_page_config(page_title="Fayos Marvel Tech Company", layout="wide")

# tiny theme + CSS
st.markdown(
    """
    <style>
    .stApp { background: linear-gradient(180deg,#071024 0%, #02101a 100%); color: #e6eef8; }
    .hero-card { display:flex; gap:18px; align-items:center; padding:18px; border-radius:12px;
                 background: rgba(255,255,255,0.02); backdrop-filter: blur(4px); border:1px solid rgba(255,255,255,0.03);} 
    .hero-title { font-size:28px; font-weight:800; margin:0 0 8px 0; color:#f8fbff; text-transform:capitalize; }
    .hero-sub { margin:0 0 12px 0; color:#d6e8ff; line-height:1.45; }
    .sidebar-logo { width: 100%; border-radius:8px; margin-bottom: 8px; }
    </style>
    """,
    unsafe_allow_html=True,
)

# Sidebar: logo + nav
with st.sidebar:
    local_logo = os.path.join(os.getcwd(), "assets", "logo.png")
    fallback = "/mnt/data/ChatGPT Image Nov 7, 2025, 12_11_34 PM.png"
    if os.path.exists(local_logo):
        st.image(local_logo, use_column_width=True, output_format="PNG")
    elif os.path.exists(fallback):
        st.image(fallback, use_column_width=True, output_format="PNG")
    else:
        st.markdown("**Fayos Marvel Tech Company**")

    st.markdown("---")
    if st.session_state.get("logged_in"):
        page_choice = st.radio("Menu", ["Dashboard", "Settings", "Account", "Transactions", "Logout"], index=0)
    else:
        page_choice = st.radio("Menu", ["Home", "Signup", "Login"], index=0)

    # Map radio to query params/page
    if page_choice == "Home":
        st.experimental_set_query_params(page="signup")
    elif page_choice == "Signup":
        st.experimental_set_query_params(page="signup")
    elif page_choice == "Login":
        st.experimental_set_query_params(page="login")
    elif page_choice == "Dashboard":
        st.experimental_set_query_params(page="dashboard")
    elif page_choice == "Settings":
        st.experimental_set_query_params(page="settings")
    elif page_choice == "Account":
        st.experimental_set_query_params(page="account")
    elif page_choice == "Transactions":
        st.experimental_set_query_params(page="transactions")
    elif page_choice == "Logout":
        do_logout()
        go_to_page("signup")


# Header / hero
left_col, right_col = st.columns([2.6, 1.4])
with left_col:
    st.markdown(
        """
        <div class="hero-card">
          <div style="flex:1">
            <h1 class="hero-title">fayos marvel tech company</h1>
            <div class="hero-sub">
              Fayos Marvel tech company is a leading IT services provider,
              dedicated to delivering innovative technology solutions to
              drive business growth and efficiency.<br><br>
              Our expertise spans IT infrastructure management, cybersecurity,
              cloud computing, and software development.
            </div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
with right_col:
    if os.path.exists(local_logo):
        st.image(local_logo, use_column_width=True)
    elif os.path.exists(fallback):
        st.image(fallback, use_column_width=True)

# show top message if any
if st.session_state.get("message"):
    st.info(st.session_state["message"])

page = current_page()

# ----------------------------
# Pages: signup / login / dashboard / settings / account / transactions
# ----------------------------
if page == "signup":
    col1, col2 = st.columns([1, 1])
    with col1:
        st.header("Create account")
        with st.form("signup_form"):
            email = st.text_input("Email", key="signup_email")
            password = st.text_input("Create password", type="password", key="signup_password")
            confirm_password = st.text_input("Confirm password", type="password", key="signup_confirm")
            is_18_or_older = st.checkbox("I confirm I am 18 years old or older", key="signup_age")
            id_image = st.file_uploader("Upload a photo of your ID (jpg/png)", type=["png", "jpg", "jpeg"], key="signup_id")
            submitted = st.form_submit_button("Sign up")

        if submitted:
            errors = []
            if not email or not email.strip():
                errors.append("Email is required.")
            elif not is_valid_email(email.strip()):
                errors.append("Please enter a valid email.")

            if not password:
                errors.append("Password is required.")
            elif len(password) < 8:
                errors.append("Password must be at least 8 characters long.")

            if password != confirm_password:
                errors.append("Passwords do not match.")

            if not is_18_or_older:
                errors.append("You must confirm you are 18+ to sign up.")

            if not id_image:
                errors.append("An ID image is required.")

            if errors:
                for e in errors:
                    st.error(e)
            else:
                exists, reason = check_user_exists(email.strip())
                if exists:
                    st.error("Account already exists for that email. Please use password reset (or sign in).")
                else:
                    with st.spinner("Creating account and uploading ID..."):
                        ok, payload = create_auth_user(email.strip(), password)
                        if not ok:
                            st.error(f"Failed to create Auth user: {payload}")
                        else:
                            # extract auth_user_id as best-effort
                            auth_user_id = None
                            if isinstance(payload, dict):
                                if "user" in payload and isinstance(payload["user"], dict):
                                    auth_user_id = payload["user"].get("id") or payload["user"].get("sub")
                                elif "data" in payload and isinstance(payload["data"], dict) and "user" in payload["data"]:
                                    auth_user_id = payload["data"]["user"].get("id") or payload["data"]["user"].get("sub")
                                elif "id" in payload:
                                    auth_user_id = payload.get("id")
                                else:
                                    for v in payload.values():
                                        if isinstance(v, dict) and "id" in v:
                                            auth_user_id = v.get("id")
                                            break
                            if not auth_user_id:
                                auth_user_id = str(uuid4())

                            filename = id_image.name if hasattr(id_image, "name") else f"id_{uuid4().hex}.jpg"
                            timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                            path = f"users/{auth_user_id}/{timestamp}_{filename}"

                            ok_upload, upload_resp = upload_id_image_to_storage(id_image, path)
                            if not ok_upload:
                                st.error(f"Failed to upload ID image: {upload_resp}")
                            else:
                                image_public_url = upload_resp
                                ok_meta, meta_resp = save_metadata_to_table(email.strip(), auth_user_id, is_18_or_older, path, image_public_url)
                                if not ok_meta:
                                    st.error(f"Failed to save metadata: {meta_resp}")
                                else:
                                    st.success("Account created and metadata saved! ✅")
                                    st.info("Now please log in from the Login page.")
                                    if st.button("Go to Login page"):
                                        go_to_page("login")

    with col2:
        st.header("Why sign up?")
        st.write(
            "After you create an account, you must return to the Login page and sign in using the password you chose. "
            "Only after a successful login will you be able to view the dashboard."
        )
        st.write("If you already have an account, go to the Login page:")
        if st.button("Go to Login"):
            go_to_page("login")

elif page == "login":
    st.title("Login")
    st.write("Enter your email and password to sign in.")
    with st.form("login_form_page"):
        login_email = st.text_input("Email", key="page_login_email")
        login_password = st.text_input("Password", type="password", key="page_login_password")
        login_submitted = st.form_submit_button("Login")

    if login_submitted:
        if not login_email or not login_password:
            st.error("Email and password are required to login.")
        else:
            with st.spinner("Signing in..."):
                ok, payload = sign_in_user(login_email.strip(), login_password)
                if not ok:
                    st.error(f"Login failed: {payload}")
                    # show quick action buttons
                    colx, coly = st.columns(2)
                    with colx:
                        if st.button("Resend confirmation email"):
                            ok2, msg2 = resend_confirmation(login_email.strip())
                            if ok2:
                                st.success(msg2)
                            else:
                                st.error(msg2)
                    with coly:
                        if st.button("Forgot password / Reset"):
                            ok3, msg3 = send_password_reset(login_email.strip())
                            if ok3:
                                st.success(msg3)
                            else:
                                st.error(msg3)
                else:
                    st.session_state["logged_in"] = True
                    st.session_state["user_email"] = login_email.strip()
                    st.session_state["message"] = f"Welcome, {login_email.strip()}!"
                    go_to_page("dashboard")

    st.markdown("---")
    if st.button("Back to Sign up"):
        go_to_page("signup")

# ----------------------------
# Dashboard (top-tab layout) with storage-backed course images
# ----------------------------
elif page == "dashboard":
    if not st.session_state.get("logged_in"):
        st.warning("You must be logged in to view the dashboard. Redirecting to login...")
        go_to_page("login")
    else:
        if "theme" not in st.session_state:
            st.session_state["theme"] = "dark"

        # Theme CSS
        if st.session_state["theme"] == "dark":
            st.markdown(
                """<style>
                .stApp { background: linear-gradient(180deg,#071024 0%, #02101a 100%); color: #e6eef8; }
                .course-card { background: rgba(255,255,255,0.03); padding:12px; border-radius:10px; margin-bottom:12px; }
                .course-img-wrap { text-align:center; margin-bottom:8px; }
                </style>""",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                """<style>
                .stApp { background: linear-gradient(180deg,#ffffff 0%, #f3f6fb 100%); color: #0b1a2b; }
                .course-card { background: #ffffff; padding:12px; border-radius:10px; box-shadow: 0 4px 12px rgba(2,6,23,0.06); margin-bottom:12px; }
                .course-img-wrap { text-align:center; margin-bottom:8px; }
                </style>""",
                unsafe_allow_html=True,
            )

        st.markdown(f"### Dashboard — Welcome, **{st.session_state.get('user_email')}**")

        tab_home, tab_services, tab_contact, tab_payment, tab_notifs, tab_theme, tab_tx = st.tabs(
            ["Home", "Services", "Contact", "Payment", "Notifications", "Theme", "Transactions"]
        )

        def _generate_courses():
            base = [
                ("Python for Beginners", 19.0), ("Advanced Python", 29.0),
                ("Data Structures & Algorithms (Python)", 39.0), ("Web Development with Flask", 24.0),
                ("Django Fullstack", 34.0), ("JavaScript Essentials", 19.0),
                ("React from Scratch", 29.0), ("Next.js Practical", 34.0),
                ("TypeScript Mastery", 29.0), ("Node.js & Express", 24.0),
                ("Databases with PostgreSQL", 29.0), ("SQL for Data Analysis", 19.0),
                ("Machine Learning Intro", 49.0), ("Deep Learning with PyTorch", 59.0),
                ("Data Engineering Basics", 39.0), ("DevOps & CI/CD", 34.0),
                ("Docker & Kubernetes", 39.0), ("System Design Essentials", 44.0),
                ("Cloud Fundamentals (AWS)", 39.0), ("Cloud on GCP", 39.0),
                ("Mobile Dev with Flutter", 29.0), ("iOS App Development (Swift)", 34.0),
                ("Android Development (Kotlin)", 34.0), ("Cybersecurity Basics", 24.0),
                ("Ethical Hacking Intro", 39.0), ("Blockchain Fundamentals", 34.0),
                ("Smart Contracts with Solidity", 44.0), ("Data Visualization (Plotly)", 24.0),
                ("Natural Language Processing", 49.0), ("Interview Prep - Algorithms", 29.0),
            ]
            courses = []
            for i, (title, price) in enumerate(base, start=1):
                courses.append({
                    "id": i,
                    "title": title,
                    "price_usd": float(price),
                    "duration_hours": 10 + (i % 5) * 5,
                    "level": ["Beginner", "Intermediate", "Advanced"][i % 3],
                })
            return courses

        courses = _generate_courses()

        # session state init for cart already handled above

        # ---------- Home tab ----------
        with tab_home:
            st.subheader("Available Programming Courses")

            # UPLOAD TO SUPABASE STORAGE: upload course image and record public URL
            with st.expander("Upload course images (stored to Supabase Storage)"):
                col_i1, col_i2 = st.columns([1, 2])
                with col_i1:
                    chosen_id = st.number_input("Course ID to set image for", min_value=1, max_value=len(courses), step=1, value=1)
                with col_i2:
                    up_file = st.file_uploader("Choose image for selected course (png/jpg)", type=["png", "jpg", "jpeg"], key="upload_course_img")
                if st.button("Save course image"):
                    if up_file is None:
                        st.warning("Please choose an image file first.")
                    else:
                        try:
                            # Read bytes
                            file_bytes = up_file.getvalue() if hasattr(up_file, "getvalue") else up_file.read()
                            # Choose extension
                            ext = "png"
                            try:
                                mime = up_file.type
                                if mime and "jpeg" in mime:
                                    ext = "jpg"
                                elif mime and "png" in mime:
                                    ext = "png"
                            except Exception:
                                pass
                            # Path in storage
                            path = f"course_images/course_{chosen_id}_{uuid4().hex}.{ext}"

                            # Upload (best-effort)
                            up_res = None
                            upload_ok = False
                            upload_err = None
                            data_u = None
                            try:
                                up_res = supabase.storage.from_(BUCKET_NAME).upload(path, file_bytes)
                                ok_u, data_u, err_u = _parse_supabase_response(up_res)
                                upload_ok = ok_u
                                upload_err = err_u
                            except Exception as e_upload:
                                upload_err = str(e_upload)

                            # Get public URL
                            url_res = None
                            pub = None
                            url_ok = False
                            url_err = None
                            datu = None
                            try:
                                url_res = supabase.storage.from_(BUCKET_NAME).get_public_url(path)
                                oku, datu, erru = _parse_supabase_response(url_res)
                                url_ok = oku
                                url_err = erru
                                if oku:
                                    if isinstance(datu, dict):
                                        pub = datu.get("publicUrl") or datu.get("publicURL") or datu.get("public_url")
                                    else:
                                        pub = str(datu)
                                else:
                                    pub = None
                            except Exception as e:
                                url_err = str(e)

                            # DEBUG panel (visible when DEBUG secret is set)
                            if st.secrets.get("DEBUG", "") == "1":
                                st.markdown("**DEBUG: Upload response (raw)**")
                                st.write(repr(up_res))
                                st.markdown("**DEBUG: Parsed upload response**")
                                st.write({"ok": upload_ok, "data": data_u, "error": upload_err})
                                st.markdown("**DEBUG: get_public_url raw response**")
                                st.write(repr(url_res))
                                st.markdown("**DEBUG: Parsed get_public_url**")
                                st.write({"ok": url_ok, "public_url": pub, "error": url_err})

                            if url_ok and pub:
                                st.session_state["course_images"][str(chosen_id)] = pub
                                st.success(f"Uploaded and saved image for course {chosen_id}")
                            else:
                                st.error(f"Could not get public URL: {url_err or upload_err or 'unknown error'}")

                        except Exception as e:
                            st.error(f"Error uploading image: {e}")

            # Catalog view
            view_mode = st.radio("View as", ["Cards", "Table"], index=0, horizontal=True)
            if view_mode == "Table":
                df_display = pd.DataFrame(courses)[["id", "title", "level", "duration_hours", "price_usd"]].copy()
                df_display.rename(columns={"duration_hours": "hours", "price_usd": "price (USD)"}, inplace=True)
                st.dataframe(df_display, use_container_width=True)
                st.markdown("**Quick add by ID**")
                col_q1, col_q2 = st.columns([1, 1])
                with col_q1:
                    quick_id = st.number_input("Course ID", min_value=1, max_value=len(courses), step=1, value=1, key="quick_add_id")
                with col_q2:
                    if st.button("Add to cart (by ID)"):
                        chosen = next((c for c in courses if c["id"] == int(quick_id)), None)
                        if chosen:
                            st.session_state["cart"].append(chosen)
                            st.success(f'Added "{chosen["title"]}" to cart.')
            else:
                for c in courses:
                    cid = str(c["id"])
                    with st.container():
                        st.markdown('<div class="course-card">', unsafe_allow_html=True)
                        st.markdown('<div class="course-img-wrap">', unsafe_allow_html=True)
                        if cid in st.session_state["course_images"]:
                            try:
                                st.image(st.session_state["course_images"][cid], use_column_width=False, width=300)
                            except Exception:
                                st.text("Could not display uploaded image.")
                        else:
                            st.image("https://via.placeholder.com/300x140.png?text=Course+Image", width=300)
                        st.markdown('</div>', unsafe_allow_html=True)

                        st.markdown(f"**{c['title']}**")
                        st.markdown(f"{c.get('level','')} • {c.get('duration_hours', '')} hrs")
                        st.markdown(f"**Price: ${c['price_usd']:.2f}**")

                        col_b1, col_b2 = st.columns([1, 3])
                        with col_b1:
                            if st.button(f"Add (image) #{c['id']}", key=f"imgadd_{c['id']}"):
                                st.session_state["cart"].append(c)
                                st.success(f'Added "{c["title"]}" to cart.')
                        with col_b2:
                            if st.button(f"Add to cart #{c['id']}", key=f"addbtn_{c['id']}"):
                                st.session_state["cart"].append(c)
                                st.success(f'Added "{c["title"]}" to cart.')
                        st.markdown('</div>', unsafe_allow_html=True)

        # ---------- Services ----------
        with tab_services:
            st.subheader("Services")
            st.info("No items to display in Services yet.")

        # ---------- Contact ----------
        with tab_contact:
            st.subheader("Contact")
            st.markdown("Reach us at:")
            st.markdown(f"- **Email:** fayosmarvel2005@gmail.com")
            st.markdown(f"- **Phone:** +2347035807145")
            st.markdown("You can upload a small cover image for the Contact page (optional):")
            contact_img = st.file_uploader("Upload contact page image (optional)", type=["png","jpg","jpeg"], key="contact_img_upload")
            if contact_img:
                try:
                    file_bytes = contact_img.getvalue() if hasattr(contact_img, "getvalue") else contact_img.read()
                    path = f"contact/contact_{uuid4().hex}.png"
                    try:
                        supabase.storage.from_(BUCKET_NAME).upload(path, file_bytes)
                    except Exception:
                        pass
                    url_res = supabase.storage.from_(BUCKET_NAME).get_public_url(path)
                    oku, datu, erru = _parse_supabase_response(url_res)
                    if oku:
                        pub = datu.get("publicUrl") if isinstance(datu, dict) else str(datu)
                        st.image(pub, caption="Contact image", use_column_width=True)
                    else:
                        st.image(contact_img, caption="Contact image (local)", use_column_width=True)
                except Exception:
                    st.text("Could not display uploaded image.")

        # ---------- Payment ----------
        with tab_payment:
            st.subheader("Payment")
            st.info("No payment methods connected. This demo simulates checkout and records transactions to the `transactions` table.")

        # ---------- Notifications ----------
        with tab_notifs:
            st.subheader("Notifications")
            if "notifications" not in st.session_state or len(st.session_state.get("notifications", [])) == 0:
                st.info("No notifications.")
            else:
                for n in reversed(st.session_state["notifications"]):
                    st.write("• " + n)
            if st.button("Clear notifications (tab)"):
                st.session_state["notifications"] = []

        # ---------- Theme ----------
        with tab_theme:
            st.subheader("Theme")
            st.write("Toggle application theme:")
            col_t1, col_t2 = st.columns([1, 1])
            with col_t1:
                if st.button("Set Light Theme"):
                    st.session_state["theme"] = "light"
                    go_to_page("dashboard")
            with col_t2:
                if st.button("Set Dark Theme"):
                    st.session_state["theme"] = "dark"
                    go_to_page("dashboard")

        # ---------- Transactions tab (quick) ----------
        with tab_tx:
            st.subheader("Transactions")
            st.info("Use the Transactions page for a full list and CSV export.")

        # ---------- Cart summary ----------
        st.markdown("---")
        st.subheader("Cart Summary")
        if len(st.session_state["cart"]) == 0:
            st.info("Cart is empty.")
        else:
            total = sum(item["price_usd"] for item in st.session_state["cart"])
            for idx, item in enumerate(st.session_state["cart"], start=1):
                st.write(f'{idx}. {item["title"]} — ${item["price_usd"]:.2f}')
            st.markdown(f"**Total: ${total:.2f}**")
            if st.button("Checkout / Purchase (simulate)"):
                purchases = []
                for item in st.session_state["cart"]:
                    purchases.append({
                        "email": st.session_state.get("user_email"),
                        "course_title": item["title"],
                        "price_usd": float(item["price_usd"]),
                        "created_at": datetime.utcnow().isoformat(),
                    })
                try:
                    res = supabase.table("transactions").insert(purchases).execute()
                    ok, data, err = _parse_supabase_response(res)
                    if ok:
                        st.success("Purchase recorded. Thank you!")
                        st.session_state.setdefault("notifications", []).append(f"Purchased {len(purchases)} course(s) for ${total:.2f}")
                        st.session_state["cart"] = []
                    else:
                        st.error(f"Purchase failed to record: {err}")
                except Exception as e:
                    st.error(f"Error recording purchase: {e}")

# ----------------------------
# Transactions page (full list + CSV export)
# ----------------------------
elif page == "transactions":
    if not st.session_state.get("logged_in"):
        st.warning("Please log in to view transactions.")
        go_to_page("login")
    else:
        st.header("My Transactions")
        try:
            user_email = st.session_state.get("user_email")
            q = supabase.table("transactions").select("id, course_title, price_usd, created_at").eq("email", user_email).order("created_at", desc=True).execute()
            ok, data, err = _parse_supabase_response(q)
            if not ok:
                st.error(f"Could not fetch transactions: {err}")
            else:
                txs = data or []
                if isinstance(txs, dict) and "data" in txs:
                    txs = txs.get("data") or []
                df = pd.DataFrame(txs)
                if df.empty:
                    st.info("No transactions yet.")
                else:
                    if "created_at" in df.columns:
                        df["created_at"] = pd.to_datetime(df["created_at"])
                    st.dataframe(df, use_container_width=True)
                    csv = df.to_csv(index=False).encode("utf-8")
                    st.download_button("Export CSV", csv, file_name="transactions.csv", mime="text/csv")
        except Exception as e:
            st.error(f"Error loading transactions: {e}")

# ----------------------------
# Settings / Account pages
# ----------------------------
elif page == "settings":
    if not st.session_state.get("logged_in"):
        st.warning("Please log in to access settings.")
        go_to_page("login")
    else:
        st.header("Settings")
        st.write("Update app settings and preferences here.")
        with st.form("settings_form"):
            display_name = st.text_input("Display name", value=st.session_state.get("user_email") or "")
            save = st.form_submit_button("Save settings")
        if save:
            try:
                res = supabase.table("users").update({"display_name": display_name}).eq("email", st.session_state.get("user_email")).execute()
                ok, data, err = _parse_supabase_response(res)
                if ok:
                    st.success("Settings updated.")
                else:
                    st.error(f"Could not save settings: {err}")
            except Exception as e:
                st.error(f"Error saving settings: {e}")

elif page == "account":
    if not st.session_state.get("logged_in"):
        st.warning("Please log in to view account.")
        go_to_page("login")
    else:
        st.header("Account")
        st.write(f"Signed in as: **{st.session_state.get('user_email')}**")
        if st.button("Logout"):
            do_logout()

else:
    st.info("Unknown page. Returning to signup.")
    go_to_page("signup")

st.markdown("---")
st.caption(
    "Notes: If your Storage bucket is private, change the code to use signed URLs. "
    "Enable RLS and policies in production and limit access to service keys."
)

# Optional admin expander
with st.expander("Admin (dangerous) - Remove test users"):
    admin_key = st.text_input("Admin key", type="password")
    if st.button("Delete all test users (email contains 'test')"):
        if admin_key == ADMIN_KEY and ADMIN_KEY != "":
            try:
                del_res = supabase.table("users").delete().ilike("email", "%test%").execute()
                ok, data, err = _parse_supabase_response(del_res)
                if not ok:
                    st.error(f"Deletion failed: {err}")
                else:
                    st.success("Deleted matching test users.")
            except Exception as e:
                st.error(f"Error deleting: {e}")
        else:
            st.error("Invalid admin key.")
