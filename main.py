import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Page config (IMPORTANT: should be first Streamlit command) ---
st.set_page_config(page_title="Secure Data System", layout="centered")

# --- Session State Init ---
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "reauthorized" not in st.session_state:
    st.session_state.reauthorized = True
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

# --- Encryption Setup ---
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# --- Utility Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, input_passkey):
    hashed_input = hash_passkey(input_passkey)
    for record in st.session_state.stored_data.values():
        if record["encrypted_text"] == encrypted_text and record["passkey"] == hashed_input:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# --- UI Layout ---
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("🔸 Navigation", menu)

# --- Home Page ---
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.markdown("Use this tool to **securely store and retrieve text data** using a passkey.")

# --- Store Data Page ---
elif choice == "Store Data":
    st.subheader("📥 Store Data Securely")
    data = st.text_area("Enter your secret data:")
    passkey = st.text_input("Choose a passkey:", type="password")

    if st.button("Encrypt & Store"):
        if data and passkey:
            encrypted = encrypt_data(data)
            hashed_pass = hash_passkey(passkey)
            record_id = f"data_{len(st.session_state.stored_data) + 1}"
            st.session_state.stored_data[record_id] = {
                "encrypted_text": encrypted,
                "passkey": hashed_pass
            }
            st.success("✅ Your data was encrypted and stored securely.")
            st.code(encrypted, language="text")
        else:
            st.error("❗ Please enter both data and passkey.")

# --- Retrieve Data Page ---
elif choice == "Retrieve Data":
    if not st.session_state.reauthorized:
        st.warning("🔐 Reauthorization required after too many failed attempts.")
        st.stop()

    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_input = st.text_area("Paste your encrypted data:")
    input_passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and input_passkey:
            result = decrypt_data(encrypted_input, input_passkey)
            if result:
                st.success("🔓 Decryption successful!")
                st.code(result, language="text")
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                if attempts_left > 0:
                    st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")
                else:
                    st.session_state.reauthorized = False
                    st.warning("🚫 Too many failed attempts! Redirecting to Login...")
                    st.rerun()
        else:
            st.error("⚠️ Please provide both encrypted data and passkey.")

# --- Login Page ---
elif choice == "Login":
    st.subheader("🔐 Login to Reauthorize")
    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.reauthorized = True
            st.success("✅ Reauthorized successfully. You may now retrieve your data.")
        else:
            st.error("❌ Incorrect password. Try again.")
