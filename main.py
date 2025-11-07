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
    Normalize different supabase client responses into (ok: bool, data, error_message).
    """
    try:
        if hasattr(res, "data") or hasattr(res, "error"):
            data = getattr(res, "data", None)
            error = getattr(res, "error", None)
            ok = (error is None)
            return ok, data, error

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

    # Attempt 2: positional args
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

    - Calls modern sign_in_with_password when available.
    - On failure, checks whether the email exists and whether email is confirmed,
      and returns actionable suggestions (reset password / confirm email).
    - If DEBUG is enabled in st.secrets (DEBUG="1"), raw responses are also shown.
    """
    attempts = []

    def _parse_and_return(res, label):
        ok, data, err = _parse_supabase_response(res)
        # debug dump when enabled
        if st.secrets.get("DEBUG", "") == "1":
            st.write(f"DEBUG sign-in raw ({label}):", repr(res))
            st.write("DEBUG parsed:", ok, data, err)
        if ok:
            # prefer to return user/session info if present
            if isinstance(data, dict) and ("user" in data or "session" in data):
                return True, data
            # sometimes res has attributes
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
            return True, data or "Signed in (no user/session payload found)"
        else:
            return False, str(err) if err else f"Sign-in failed ({label}) - no error message."

    # 1) Modern call
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

    # 2) Fallback older shapes (if present)
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

    # All sign-in attempts failed — provide helpful guidance
    # Check if the user exists and whether they confirmed their email
    exists, reason = False, "unknown"
    try:
        exists, reason = check_user_exists(email)
    except Exception:
        exists, reason = False, "check_user_exists failed"

    # try to fetch auth user info to examine confirmation status (best-effort)
    email_confirmed = None
    try:
        # Many clients expose admin or api methods — try both
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
        # parse
        ok2, data2, err2 = _parse_supabase_response(auth_user) if auth_user is not None else (False, None, None)
        if ok2 and data2:
            # data2 might be the user dict or wrapped in 'user'
            u = None
            if isinstance(data2, dict):
                if data2.get("email"):
                    u = data2
                elif "user" in data2 and isinstance(data2["user"], dict):
                    u = data2["user"]
            if isinstance(u, dict):
                email_confirmed = bool(u.get("email_confirmed_at") or u.get("confirmed_at") or u.get("email_confirmed"))
    except Exception:
        email_confirmed = None

    # Compose final friendly message
    msg_parts = []
    # give raw attempts summary (concise)
    msg_parts.append("Unable to sign in. Reason(s):")
    for k, v in attempts:
        msg_parts.append(f"- {k}: {v}")

    if exists:
        if email_confirmed is False:
            msg_parts.append("- Your account exists but the email is not confirmed. Check your inbox for the confirmation email or enable confirmation in Supabase settings.")
        else:
            msg_parts.append("- The email exists. Most likely the password is incorrect. Try resetting your password.")
            msg_parts.append("  You can reset your password from the Supabase dashboard (Auth → Users → Reset password) or implement a 'Forgot password' flow.")
    else:
        msg_parts.append("- No account found for that email. Create a new account or verify the email address used during signup.")

    # Add a short actionable tip
    msg_parts.append("If you're testing, you can also create a test user directly in the Supabase dashboard and try logging in with that user's credentials.")
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
    # Try a generic rpc/endpoint if project exposes it (best-effort)
    calls.append(("rpc.reset_password", lambda: supabase.rpc("reset_password", {"email": email})))
    ok, msg, data = _try_calls(calls)
    if ok:
        return True, "Password reset requested — check your email for instructions."
    # Fall back message includes reason
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
# Upload helpers (unchanged)
# ----------------------------
def upload_id_image_to_storage(uploaded_file, path: str):
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
            inner_path = None
            try:
                if hasattr(res, "path") and getattr(res, "path"):
                    inner_path = getattr(res, "path")
                elif hasattr(res, "full_path") and getattr(res, "full_path"):
                    fp = getattr(res, "full_path")
                    prefix = f"{BUCKET_NAME}/"
                    if isinstance(fp, str) and fp.startswith(prefix):
                        inner_path = fp[len(prefix):]
                    else:
                        inner_path = fp
            except Exception:
                inner_path = None

            if inner_path:
                try:
                    url_res = supabase.storage.from_(BUCKET_NAME).get_public_url(inner_path)
                    ok2, data2, err2 = _parse_supabase_response(url_res)
                    if ok2:
                        if isinstance(data2, dict):
                            return True, data2.get("publicUrl") or data2.get("publicURL") or data2.get("public_url") or str(data2)
                        return True, str(data2)
                    else:
                        return True, f"Upload succeeded; could not obtain public URL: {err2 or data2}"
                except Exception as e:
                    return True, f"Upload succeeded; exception obtaining public URL: {e}"

            ok, data, err = _parse_supabase_response(res)
            attempts.append((desc, "parsed_ok" if ok else f"parsed_err: {err}"))
            if ok:
                try:
                    p = None
                    if isinstance(data, dict):
                        p = data.get("path") or data.get("full_path") or data.get("fullPath") or data.get("key")
                    if p:
                        prefix = f"{BUCKET_NAME}/"
                        if isinstance(p, str) and p.startswith(prefix):
                            p = p[len(prefix):]
                        url_res = supabase.storage.from_(BUCKET_NAME).get_public_url(p)
                        ok2, data2, err2 = _parse_supabase_response(url_res)
                        if ok2:
                            if isinstance(data2, dict):
                                return True, data2.get("publicUrl") or data2.get("publicURL") or data2.get("public_url") or str(data2)
                            return True, str(data2)
                        else:
                            return True, f"Upload succeeded; get_public_url failed: {err2 or data2}"
                    else:
                        return True, f"Upload seemed to succeed. Response: {data}"
                except Exception as e:
                    return True, f"Upload seemed to succeed; exception processing response: {e}"

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
    if os.path.exists(local_logo):
        st.image(local_logo, use_column_width=True, output_format="PNG")
    else:
        fallback = "/mnt/data/ChatGPT Image Nov 7, 2025, 12_11_34 PM.png"
        if os.path.exists(fallback):
            st.image(fallback, use_column_width=True, output_format="PNG")
        else:
            st.markdown("**Fayos Marvel Tech Company**")

    st.markdown("---")
    if st.session_state.get("logged_in"):
        page_choice = st.radio("Menu", ["Dashboard", "Settings", "Account", "Logout"], index=0)
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
    elif page_choice == "Logout":
        do_logout()
        # go_to_page will handle rerun/exit if needed
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
    # small decorative image or logo repeat
    if os.path.exists(local_logo):
        st.image(local_logo, use_column_width=True)
    elif os.path.exists(fallback):
        st.image(fallback, use_column_width=True)

# show top message if any
if st.session_state.get("message"):
    st.info(st.session_state["message"])

page = current_page()

# ----------------------------
# Pages: signup / login / dashboard / settings / account
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
# Dashboard: courses, cart, payments, transactions, notifications
# Replaced existing dashboard implementation with the enriched dashboard UI
# ----------------------------
elif page == "dashboard":
    # ensure logged-in
    if not st.session_state.get("logged_in"):
        st.warning("You must be logged in to view the dashboard. Redirecting to login...")
        go_to_page("login")
    else:
        # theme toggle (simple)
        if "theme" not in st.session_state:
            st.session_state["theme"] = "dark"  # default
        # small theme CSS switch
        if st.session_state["theme"] == "dark":
            st.markdown(
                """
                <style>
                .stApp { background: linear-gradient(180deg,#071024 0%, #02101a 100%); color: #e6eef8; }
                .card { background: rgba(255,255,255,0.03); padding:12px; border-radius:10px; }
                </style>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                """
                <style>
                .stApp { background: linear-gradient(180deg,#ffffff 0%, #f3f6fb 100%); color: #0b1a2b; }
                .card { background: #ffffff; padding:12px; border-radius:10px; box-shadow: 0 4px 12px rgba(2,6,23,0.06); }
                </style>
                """,
                unsafe_allow_html=True,
            )

        # Header
        st.markdown(f"### Dashboard — Welcome, **{st.session_state.get('user_email')}**")

        # Sidebar mini-controls inside main area (since main sidebar holds nav)
        col_top_left, col_top_right = st.columns([3, 1])
        with col_top_right:
            if st.button("Toggle theme"):
                st.session_state["theme"] = "light" if st.session_state["theme"] == "dark" else "dark"
                go_to_page("dashboard")  # rerun to apply theme

        # --- Course catalog: generate 30 courses ---
        # If you have a database of courses, replace this generation with a supabase.table("courses").select(...)
        def _generate_courses():
            base = [
                ("Python for Beginners", 19.0),
                ("Advanced Python", 29.0),
                ("Data Structures & Algorithms (Python)", 39.0),
                ("Web Development with Flask", 24.0),
                ("Django Fullstack", 34.0),
                ("JavaScript Essentials", 19.0),
                ("React from Scratch", 29.0),
                ("Next.js Practical", 34.0),
                ("TypeScript Mastery", 29.0),
                ("Node.js & Express", 24.0),
                ("Databases with PostgreSQL", 29.0),
                ("SQL for Data Analysis", 19.0),
                ("Machine Learning Intro", 49.0),
                ("Deep Learning with PyTorch", 59.0),
                ("Data Engineering Basics", 39.0),
                ("DevOps & CI/CD", 34.0),
                ("Docker & Kubernetes", 39.0),
                ("System Design Essentials", 44.0),
                ("Cloud Fundamentals (AWS)", 39.0),
                ("Cloud on GCP", 39.0),
                ("Mobile Dev with Flutter", 29.0),
                ("iOS App Development (Swift)", 34.0),
                ("Android Development (Kotlin)", 34.0),
                ("Cybersecurity Basics", 24.0),
                ("Ethical Hacking Intro", 39.0),
                ("Blockchain Fundamentals", 34.0),
                ("Smart Contracts with Solidity", 44.0),
                ("Data Visualization (Plotly)", 24.0),
                ("Natural Language Processing", 49.0),
                ("Interview Prep - Algorithms", 29.0),
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
        courses_df = pd.DataFrame(courses)

        # Cart stored in session
        if "cart" not in st.session_state:
            st.session_state["cart"] = []

        # Main layout: left = catalog, right = cart/transactions/notifications tabs
        left, right = st.columns([3, 1.2])

        # Left: show catalog with add-to-cart buttons
        with left:
            st.subheader("Available Programming Courses")
            # table view toggle
            view = st.radio("View as", ["Table", "Cards"], index=0, horizontal=True)
            if view == "Table":
                # show dataframe
                df_display = courses_df[["id", "title", "level", "duration_hours", "price_usd"]].copy()
                df_display.rename(columns={"duration_hours": "hours", "price_usd": "price (USD)"}, inplace=True)
                st.dataframe(df_display, use_container_width=True)
                # add purchase by id
                st.markdown("**Quick buy by ID**")
                col_a, col_b = st.columns([1, 1])
                with col_a:
                    buy_id = st.number_input("Course ID", min_value=1, max_value=len(courses), step=1, value=1)
                with col_b:
                    if st.button("Add to cart by ID"):
                        chosen = next((c for c in courses if c["id"] == int(buy_id)), None)
                        if chosen:
                            st.session_state["cart"].append(chosen)
                            st.success(f'Added "{chosen["title"]}" to cart.')
            else:
                # cards
                for c in courses:
                    with st.container():
                        st.markdown(f'<div class="card"><b>{c["title"]}</b> — {c["level"]} • {c["duration_hours"]} hrs<br>Price: ${c["price_usd"]:.2f}</div>', unsafe_allow_html=True)
                        cols = st.columns([1, 4])
                        with cols[0]:
                            if st.button(f"Add #{c['id']}", key=f"add_{c['id']}"):
                                st.session_state["cart"].append(c)
                                st.success(f'Added "{c["title"]}" to cart.')
                        with cols[1]:
                            st.write("")  # spacer

        # Right: cart, checkout, notifications, transactions quick view
        with right:
            st.subheader("Cart")
            if len(st.session_state["cart"]) == 0:
                st.info("Cart is empty.")
            else:
                total = sum(item["price_usd"] for item in st.session_state["cart"])
                for idx, item in enumerate(st.session_state["cart"], start=1):
                    st.write(f'{idx}. {item["title"]} — ${item["price_usd"]:.2f}')
                st.markdown(f"**Total: ${total:.2f}**")
                if st.button("Checkout / Purchase"):
                    # simulate payment and record transaction(s) to Supabase 'transactions' table
                    purchases = []
                    for item in st.session_state["cart"]:
                        purchases.append({
                            "email": st.session_state.get("user_email"),
                            "course_title": item["title"],
                            "price_usd": float(item["price_usd"]),
                            "created_at": datetime.utcnow().isoformat(),
                        })
                    # insert into Supabase (best-effort)
                    try:
                        res = supabase.table("transactions").insert(purchases).execute()
                        ok, data, err = _parse_supabase_response(res)
                        if ok:
                            st.success("Purchase recorded. Thank you!")
                            # push a simple notification into session notifications
                            if "notifications" not in st.session_state:
                                st.session_state["notifications"] = []
                            st.session_state["notifications"].append(f"Purchased {len(purchases)} course(s) for ${total:.2f}")
                            # clear cart
                            st.session_state["cart"] = []
                        else:
                            st.error(f"Purchase failed to record: {err}")
                    except Exception as e:
                        st.error(f"Error recording purchase: {e}")

            st.markdown("---")
            # Notifications
            st.subheader("Notifications")
            if "notifications" not in st.session_state:
                st.session_state["notifications"] = []
            if len(st.session_state["notifications"]) == 0:
                st.info("No notifications.")
            else:
                for n in reversed(st.session_state["notifications"]):
                    st.write("• " + n)
            if st.button("Clear notifications"):
                st.session_state["notifications"] = []

            st.markdown("---")
            # quick links
            if st.button("Go to Services"):
                go_to_page("signup")  # or your services page
            if st.button("Contact"):
                st.info("Email: hello@fayosmarvel.tech — we'll add a contact form soon.")

            st.markdown("---")
            # Transactions quick link -> go to transactions page (sidebar also has it)
            if st.button("View my transactions"):
                go_to_page("account")  # we'll show transactions in 'account' page

        # End dashboard content

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
