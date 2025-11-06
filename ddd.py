from supabase import create_client, Client
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

# Check they loaded
print("URL:", SUPABASE_URL)
print("Key:", SUPABASE_KEY[:8], "...")

# Create Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Insert data into 'users' table
data = {"email": "fayo@example.com", "name": "Fayosola"}
supabase.table("users").update({"name":"Fay"}).eq("email","fayo@example.com").execute()
supabase.table("users").delete().eq("email","fayo@example.com").execute()

resp = supabase.table("users").select("*").limit(1).execute()
print(resp)

try:
    response = supabase.table("users").insert(data).execute()
    print("Data:", response.data)
    print("Error:", response.error)
except Exception as e:
    print("Full error:", e)
