import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# ------------------- Session Initialization -------------------

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = False

if 'fernet' not in st.session_state:
    key = Fernet.generate_key()
    st.session_state.fernet = Fernet(key)

fernet = st.session_state.fernet

# ------------------- Utility Functions -------------------

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data: str) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted: str) -> str:
    return fernet.decrypt(encrypted.encode()).decode()

# ------------------- UI Config -------------------

st.set_page_config(page_title="Secure Vault Pro", page_icon="🔐")

st.title("🛡️ Secure Vault")
st.caption("A secure, encrypted data locker powered by Streamlit.")

# ------------------- Sidebar Navigation -------------------
menu = ["🏠 Home", "➕ Store Data", "🔓 Retrieve Data", "🔐 Login", "⚙️ Advanced Features"]
choice = st.sidebar.selectbox("📍 Navigate", menu)

# ------------------- Home Page -------------------

if choice == "🏠 Home":
    st.subheader("🔐 Welcome to Your Secure Vault")
    st.markdown(""" 
    🔑 **Securely Store Your Sensitive Data**  
    💡 **Only Accessible with a Correct Passkey**  
    🔒 **All Data is Encrypted for Maximum Security**  
    🛡️ **3 Failed Attempts = Lockout**  
    🔏 **In-memory Data, No External Database Used**

    ### Features:
    - **Encrypt & Store**: Securely store personal data with a passkey.
    - **Decrypt & Retrieve**: Access data only with the correct passkey.
    - **Tagging System**: Add tags to easily categorize your data.
    - **Hints for Retrieval**: Add hints to remind yourself of data contents.
    
    🚀 Start by storing your first piece of data today!
    """)

# ------------------- Store Data Page -------------------

elif choice == "➕ Store Data":
    if not st.session_state.is_logged_in:
        st.warning("🔒 Access Denied! Please login first.")
        st.stop()

    st.subheader("➕ Encrypt & Store New Data")

    unique_id = st.text_input("🔤 Unique ID for Data:", placeholder="e.g., my_bank_pin_2025")
    if unique_id in st.session_state.stored_data:
        st.warning("⚠️ This ID already exists. Please use another.")

    user_data = st.text_area("📝 Enter Your Data:", placeholder="e.g., My ATM PIN is 1234", height=150, max_chars=500)
    st.caption(f"🧾 Characters used: {len(user_data)} / 500")

    passkey = st.text_input("🔑 Enter Secret Passkey:", placeholder="At least 6 characters", type="password")
    if passkey and len(passkey) < 6:
        st.warning("⚠️ Passkey should be at least 6 characters.")

    tags = st.multiselect("🏷️ Optional Tags (for reference):", ["Personal", "Work", "Finance", "Login", "Notes"])
    hint = st.text_input("💡 Optional Hint for Retrieval:", placeholder="e.g., Used for SBI bank")

    if st.button("📥 Encrypt & Save"):
        if not unique_id or not user_data or not passkey:
            st.warning("⚠️ Please complete all required fields.")
        elif len(passkey) < 6:
            st.warning("⚠️ Passkey must be at least 6 characters.")
        elif unique_id in st.session_state.stored_data:
            st.error("🚫 This ID already exists. Please choose another one.")
        else:
            encrypted_text = encrypt_data(user_data)
            hashed_pass = hash_passkey(passkey)
            st.session_state.stored_data[unique_id] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_pass,
                "hint": hint,
                "tags": tags
            }
            st.success("✅ Data encrypted and stored successfully!")
            with st.expander("🔐 Encrypted Data Preview"):
                st.code(encrypted_text, language="plaintext")

# ------------------- Retrieve Data Page -------------------

elif choice == "🔓 Retrieve Data":
    if not st.session_state.is_logged_in:
        st.warning("🔒 Access Denied! Please login first.")
        st.stop()

    st.subheader("🔓 Retrieve and Decrypt Your Data")

    unique_id = st.text_input("🆔 Enter Data ID:", placeholder="e.g., my_bank_pin_2025")
    passkey = st.text_input("🔑 Enter Passkey:", placeholder="Enter the correct secret passkey", type="password")

    if st.button("🔍 Decrypt"):
        if not unique_id or not passkey:
            st.warning("⚠️ Both fields are required.")
        elif unique_id in st.session_state.stored_data:
            data_obj = st.session_state.stored_data[unique_id]
            if hash_passkey(passkey) == data_obj["passkey"]:
                decrypted = decrypt_data(data_obj["encrypted_text"])
                st.success("✅ Data Decrypted Successfully!")
                st.text_area("📖 Your Decrypted Data:", decrypted, height=150, disabled=True)

                if data_obj.get("hint"):
                    st.info(f"💡 Hint: {data_obj['hint']}")
                if data_obj.get("tags"):
                    st.caption(f"🏷️ Tags: {', '.join(data_obj['tags'])}")

                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey! Attempts left: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🚫 Too many failed attempts. Redirecting to Login...")
                    st.session_state.is_logged_in = False
                    st.experimental_rerun()
        else:
            st.error("❗ No data found with this ID.")

# ------------------- Login Page -------------------

elif choice == "🔐 Login":
    st.subheader("🔐 Re-Login to Continue")

    master_pass = st.text_input("🔑 Enter Master Password:", type="password")

    if st.button("🔁 Login"):
        if master_pass == "admin123":  # Replace this with a secure password check method!
            st.session_state.failed_attempts = 0
            st.session_state.is_logged_in = True
            st.success("✅ Logged in successfully!")
        else:
            st.error("❌ Incorrect password.")
            st.session_state.failed_attempts = 0

# ------------------- Advanced Features -------------------

elif choice == "⚙️ Advanced Features":
    st.subheader("⚙️ Advanced Features & Tools")

    if not st.session_state.is_logged_in:
        st.warning("🔒 Please login to access advanced tools.")
        st.stop()

    st.markdown("Use these tools to manage or inspect your secure vault system.")

    st.write("### 🗃️ Stored Data Overview")
    if st.session_state.stored_data:
        for uid, info in st.session_state.stored_data.items():
            with st.expander(f"🔐 {uid}"):
                st.write("**Hint:**", info["hint"] or "No hint")
                st.write("**Tags:**", ", ".join(info["tags"]) if info["tags"] else "No tags")
                st.code(info["encrypted_text"], language="plaintext")
    else:
        st.info("ℹ️ No data stored yet.")

    if st.button("🧹 Clear All Stored Data"):
        st.session_state.stored_data = {}
        st.success("✅ All data cleared from memory.")
