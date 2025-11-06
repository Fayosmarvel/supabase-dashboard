import os
import re
import io
import base64
from datetime import datetime
from uuid import uuid4

import streamlit as st
from supabase import create_client
import pandas as pd
from PIL import Image

# ----------------------------
# Read secrets from Streamlit
# ----------------------------
# Streamlit Cloud provides st.secrets; local dev can set a local secrets.toml or fallback to env vars if you prefer.
# Example (local): create a file .streamlit/secrets.toml with the same keys for local testing.
st.write("Loaded secrets:", list(st.secrets.keys()))
try:
    SUPABASE_URL = st.secrets["SUPABASE_URL"]
    SUPABASE_KEY = st.secrets["SUPABASE_KEY"]
    BUCKET_NAME = st.secrets.get("SUPABASE_BUCKET", "id_uploads")
    ADMIN_KEY = st.secrets.get("ADMIN_KEY", "")
except Exception as e:
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


def create_auth_user(email: str, password: str):
    """Create a Supabase Auth user using sign_up (works across client versions)."""
    try:
        res = supabase.auth.sign_up({"email": email, "password": password})
    except Exception:
        try:
            res = supabase.auth.sign_up(email=email, password=password)
        except Exception as e:
            return False, f"Exception calling auth.sign_up: {e}"

    ok, data, err = _parse_supabase_response(res)
    if ok:
        return True, data
    else:
        return False, err


def upload_id_image_to_storage(uploaded_file, path: str):
    """
    Upload bytes to Supabase Storage bucket at given path.
    Returns (ok: bool, public_url_or_error_str)
    """
    try:
        file_bytes = uploaded_file.getvalue()
        # Try bytes upload; if client complains, try file-like
        try:
            res = supabase.storage.from_(BUCKET_NAME).upload(path, file_bytes)
        except Exception:
            file_obj = io.BytesIO(file_bytes)
            res = supabase.storage.from_(BUCKET_NAME).upload(path, file_obj)

        ok, data, err = _parse_supabase_response(res)
        if not ok:
            # we continue to attempt to get a public url; but if upload failed, return error
            return False, f"Upload failed: {err}"

        # Get public URL (works if bucket is public)
        try:
            url_res = supabase.storage.from_(BUCKET_NAME).get_public_url(path)
            ok2, data2, err2 = _parse_supabase_response(url_res)
            if ok2:
                # data2 may be a dict or string
                if isinstance(data2, dict):
                    return True, data2.get("publicUrl") or data2.get("publicURL") or data2.get("public_url") or str(data2)
                return True, str(data2)
            else:
                return False, f"Failed to get public URL: {err2 or data2}"
        except Exception as e:
            return False, f"Exception when getting public URL: {e}"

    except Exception as e:
        return False, f"Exception uploading file: {e}"


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
# UI
# ----------------------------
st.set_page_config(page_title="Signup (Supabase Auth) & Dashboard", layout="wide")
st.title("Signup (Supabase Auth) & Dashboard")

st.markdown(
    "This app uses Supabase Auth to create accounts and Supabase Storage to store ID images. "
    "Keep service keys secret in Streamlit Secrets."
)

col1, col2 = st.columns([1, 1])

with col1:
    st.header("Create account")
    with st.form("signup_form"):
        email = st.text_input("Email")
        password = st.text_input("Create password", type="password")
        confirm_password = st.text_input("Confirm password", type="password")
        is_18_or_older = st.checkbox("I confirm I am 18 years old or older")
        id_image = st.file_uploader("Upload a photo of your ID (jpg/png)", type=["png", "jpg", "jpeg"])
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
            with st.spinner("Creating account and uploading ID..."):
                ok, payload = create_auth_user(email.strip(), password)
                if not ok:
                    st.error(f"Failed to create Auth user: {payload}")
                else:
                    # Try to extract auth user id from payload
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
                        # fallback: synthetic id (not ideal but keeps flow)
                        auth_user_id = str(uuid4())

                    # Build storage path and upload
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
                            st.success("Account created and metadata saved!")

with col2:
    st.header("Dashboard (users)")
    # Robust fetch: try to select expected columns, fallback if DB doesn't have them
    try:
        users_res = supabase.table("users").select("email,auth_user_id,is_adult,created_at,id_image_public_url").order("created_at", desc=True).limit(500).execute()
        ok, data, err = _parse_supabase_response(users_res)
        if not ok:
            err_str = str(err) if err is not None else ""
            if "does not exist" in err_str or "column" in err_str:
                # fallback to select all
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
            # In case only path is stored (no public URL), attempt to create a public URL pattern
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
                # try to construct a public url from path using client (best-effort)
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

st.markdown("---")
st.caption(
    "Notes: If your Storage bucket is private, change the code to use signed URLs. "
    "Enable RLS and policies in production and limit access to service keys."
)

# Optional: small admin panel to clear test users (dangerous in prod) - protected by a simple text key
with st.expander("Admin (dangerous) - Remove test users"):
    admin_key = st.text_input("Admin key", type="password")
    if st.button("Delete all test users (email contains 'test')"):
        if admin_key == os.getenv("ADMIN_KEY", "") and admin_key != "":
            try:
                del_res = supabase.table("users").delete().ilike("email", "%test%").execute()
                if del_res.error:
                    st.error(f"Deletion failed: {del_res.error}")
                else:
                    st.success("Deleted matching test users.")
            except Exception as e:
                st.error(f"Error deleting: {e}")
        else:
            st.error("Invalid admin key.")
