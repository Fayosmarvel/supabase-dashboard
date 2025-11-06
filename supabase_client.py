from supabase import create_client
from dotenv import load_dotenv
import os

load_dotenv()  # loads .env

SUPABASE_URL = os.getenv("https://hdreqohjattpyulmwohr.supabase.co")
SUPABASE_KEY = os.getenv("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImhkcmVxb2hqYXR0cHl1bG13b2hyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjIxMDEyMTMsImV4cCI6MjA3NzY3NzIxM30.HBw07ikLp9PpbbOf8i4MpcJ7ALLwit665l-Sm9gwnmw")  # or service key on server

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)