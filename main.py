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
    Handles objects with .data/.error, objects with .status_code/.data/.json, or plain dicts.
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


def upload_id_image_to_storage(uploaded_file, path: str):
    """
    Robust upload helper for Supabase Storage that understands UploadResponse objects.
    Returns (ok: bool, public_url_or_error_str).
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
# UI / Pages
# ----------------------------
# -- hero / header (two-column card with provided logo) --
# === improved hero block (replace previous hero code) ===
st.set_page_config(page_title="Fayos Marvel Tech Company", layout="wide")

# CSS: translucent hero card (no pure white box)
st.markdown(
    """
    <style>
    .hero-card {
        display: flex;
        gap: 18px;
        align-items: center;
        padding: 18px;
        border-radius: 12px;
        background: rgba(255,255,255,0.02); /* almost transparent */
        backdrop-filter: blur(4px);
        border: 1px solid rgba(255,255,255,0.03);
        box-shadow: 0 8px 30px rgba(2,6,23,0.12);
    }
    .hero-title { font-size: 28px; font-weight: 800; margin: 0 0 8px 0; color: #e6eef8; text-transform: capitalize; }
    .hero-sub { margin: 0 0 12px 0; color: #d8e6ff; line-height: 1.45; }
    .hero-ctas { display: flex; gap:10px; margin-top:8px; }
    /* page background darken so translucent card looks good */
    .stApp {
        background: linear-gradient(180deg, #071024 0%, #02101a 100%);
        color: #e6eef8;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# layout columns
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

    c1, c2, c3 = st.columns([1, 1, 1])
    with c1:
        if st.button("Create account"):
            go_to_page("signup")
    with c2:
        if st.button("Login"):
            go_to_page("login")
    with c3:
        if st.button("Learn more"):
            st.info("We provide IT infrastructure, cloud, security, and software services. Contact us to learn more.")

    st.markdown('<div style="color:#aebfdc; font-size:12px; margin-top:8px;">Trusted partner for SMEs, startups and enterprises.</div>', unsafe_allow_html=True)

with right_col:
    # Try loading the logo from multiple possible locations (developer-friendly)
    # 1) Prefer a packaged repo file (recommended). Put your logo at ./assets/logo.png
    repo_logo = os.path.join(os.getcwd(), "assets", "logo.png")
    # 2) The absolute path you gave earlier (dev-only)
    provided_path = "/mnt/data/ChatGPT Image Nov 7, 2025, 12_11_34 PM.png"
    # 3) Allow dev uploading if needed (not persisted across runs)
    uploaded_logo = st.file_uploader("Upload logo (optional, for dev)", type=["png","jpg","jpeg"])

    logo_to_show = None
    logo_source = None

    if uploaded_logo is not None:
        try:
            logo_bytes = uploaded_logo.read()
            logo_to_show = logo_bytes
            logo_source = "uploaded"
        except Exception:
            logo_to_show = None

    if logo_to_show is None and os.path.exists(repo_logo):
        logo_to_show = repo_logo
        logo_source = "repo"
    elif logo_to_show is None and os.path.exists(provided_path):
        logo_to_show = provided_path
        logo_source = "provided"

    # Display helpful diagnostics in the UI so you can see what's happening:
    st.markdown("<div style='color:#9fb0d8; font-size:12px;'>Logo debug:</div>", unsafe_allow_html=True)
    st.text(f"Repo path: {repo_logo} (exists: {os.path.exists(repo_logo)})")
    st.text(f"Provided path: {provided_path} (exists: {os.path.exists(provided_path)})")
    if uploaded_logo is not None:
        st.text("Uploaded logo present (will use uploaded file)")

    if logo_to_show:
        try:
            # If it's raw bytes (uploaded), pass bytes; else pass path
            st.image(logo_to_show, caption="Fayos Marvel logo", use_column_width=True)
            st.success(f"Logo loaded from: {logo_source}")
        except Exception as e:
            st.error(f"Logo could not be displayed: {e}")
    else:
        st.warning("Logo could not be loaded. Place logo at ./assets/logo.png or upload it using the uploader above.")

# show top message if any
if st.session_state.get("message"):
    st.info(st.session_state["message"])

page = current_page()

if page == "signup":
    # Signup page layout
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
                # DEBUG: uncomment to inspect payload when debugging
                # if st.secrets.get("DEBUG","") == "1":
                #     st.write("sign-in payload:", payload)
                if not ok:
                    st.error(f"Login failed: {payload}")
                else:
                    st.session_state["logged_in"] = True
                    st.session_state["user_email"] = login_email.strip()
                    st.session_state["message"] = f"Welcome, {login_email.strip()}!"
                    go_to_page("dashboard")

    st.markdown("---")
    if st.button("Back to Sign up"):
        go_to_page("signup")

elif page == "dashboard":
    if not st.session_state.get("logged_in"):
        st.warning("You must be logged in to view the dashboard. Redirecting to login...")
        go_to_page("login")
    else:
        st.header(f"Dashboard (users) — Logged in as {st.session_state.get('user_email')}")
        if st.button("Logout"):
            do_logout()

        # Robust fetch: try to select expected columns, fallback if DB doesn't have them
        try:
            users_res = supabase.table("users").select("email,auth_user_id,is_adult,created_at,id_image_public_url").order("created_at", desc=True).limit(500).execute()
            ok, data, err = _parse_supabase_response(users_res)
            if not ok:
                err_str = str(err) if err is not None else ""
                if "does not exist" in err_str or "column" in err_str:
                    users_res = supabase.table("users").select("*").order("created_at", desc=True).limit(500).execute()
                    ok2, data2, err2 = _parse_supabase_response(users_res)
                    if not ok2:
                        st.error(f"Failed to load users after fallback: {err2}")
                        users_df = pd.DataFrame()
                    else:
                        users = data2 or []
                        if isinstance(users, dict) and "data" in users:
                            users = users.get("data") or []
                        users_df = pd.DataFrame(users)
                else:
                    st.error(f"Failed to load users: {err}")
                    users_df = pd.DataFrame()
            else:
                users = data or []
                if isinstance(users, dict) and "data" in users:
                    users = users.get("data") or []
                users_df = pd.DataFrame(users)

            if not users_df.empty and "created_at" in users_df.columns:
                users_df["created_at"] = pd.to_datetime(users_df["created_at"], utc=True)
        except Exception as e:
            st.error(f"Exception fetching users: {e}")
            users_df = pd.DataFrame()

        # Metrics
        col_a, col_b, col_c = st.columns(3)
        total_users = len(users_df)
        adults = int(users_df["is_adult"].sum()) if (not users_df.empty and "is_adult" in users_df.columns) else 0
        non_adults = total_users - adults

        col_a.metric("Total users", total_users)
        col_b.metric("18+ users", adults)
        col_c.metric("Under 18 (reported)", non_adults)

        st.subheader("Recent signups")
        if users_df.empty:
            st.info("No user records found yet.")
        else:
            recent_cols = [c for c in ["email", "auth_user_id", "is_adult", "created_at"] if c in users_df.columns]
            st.dataframe(users_df.loc[:, recent_cols].head(20))

            st.subheader("Latest ID preview")
            if "id_image_public_url" in users_df.columns:
                latest_with_image = users_df[users_df["id_image_public_url"].notnull() & (users_df["id_image_public_url"] != "")]
            elif "id_image_path" in users_df.columns:
                latest_with_image = users_df[users_df["id_image_path"].notnull() & (users_df["id_image_path"] != "")]
            else:
                latest_with_image = pd.DataFrame()

            if not latest_with_image.empty:
                if "id_image_public_url" in latest_with_image.columns:
                    latest_url = latest_with_image.iloc[0]["id_image_public_url"]
                    try:
                        st.image(latest_url, caption="Latest uploaded ID (public URL)", use_column_width=True)
                    except Exception:
                        st.text("Could not load latest image via public URL.")
                else:
                    try:
                        row = latest_with_image.iloc[0]
                        path = row.get("id_image_path")
                        if path:
                            url_res = supabase.storage.from_(BUCKET_NAME).get_public_url(path)
                            oku, datu, erru = _parse_supabase_response(url_res)
                            if oku:
                                if isinstance(datu, dict):
                                    pub = datu.get("publicUrl") or datu.get("publicURL") or datu.get("public_url") or str(datu)
                                else:
                                    pub = str(datu)
                                st.image(pub, caption="Latest uploaded ID (constructed URL)", use_column_width=True)
                            else:
                                st.text("Could not construct public URL for latest image.")
                        else:
                            st.text("No image path available for preview.")
                    except Exception:
                        st.text("Could not preview the latest image.")

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
