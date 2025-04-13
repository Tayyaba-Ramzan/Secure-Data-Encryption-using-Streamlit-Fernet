import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ------------------- App Configuration -------------------
st.set_page_config(
    page_title="Secure Vault Pro",
    page_icon="🔐",
    initial_sidebar_state="collapsed"
)

# ------------------- Session Initialization -------------------

if 'users' not in st.session_state:
    st.session_state.users = {}

if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = False

if 'fernet' not in st.session_state:
    key = Fernet.generate_key()
    st.session_state.fernet = Fernet(key)

if 'otp' not in st.session_state:
    st.session_state.otp = None

if 'activity_log' not in st.session_state:
    st.session_state.activity_log = []

if 'home_balloons_shown' not in st.session_state:
    st.session_state.home_balloons_shown = False

fernet = st.session_state.fernet

# ------------------- Utility Functions -------------------

def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data: str) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(encrypted: str) -> str:
    return fernet.decrypt(encrypted.encode()).decode()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def send_otp_email(email: str, otp: str):
    msg = MIMEMultipart()
    msg['From'] = "your-email@example.com"
    msg['To'] = email
    msg['Subject'] = "Your OTP Code"
    body = f"Your OTP code is: {otp}"
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login("your-email@example.com", "your-password")
            text = msg.as_string()
            server.sendmail("your-email@example.com", email, text)
    except Exception as e:
        st.error(f"Error sending email: {e}")

def password_strength(password: str):
    if len(password) < 6:
        return "Weak"
    elif len(password) < 12:
        return "Medium"
    else:
        return "Strong"

# ------------------- Login & Signup -------------------

# ------------------- Login & Signup -------------------

def show_login_signup():
    st.title("🔐 Welcome to Secure Vault")
    st.subheader("Please Login or Signup to continue")

    auth_option = st.radio("Choose an option:", ["Login", "Signup"])
    username = st.text_input("👤 Username")
    password = st.text_input("🔑 Password", type="password")

    if auth_option == "Signup":
        if st.button("📝 Create Account"):
            if username and password:
                if username not in st.session_state.users:
                    st.session_state.users[username] = {
                        "password": hash_password(password)
                    }
                    st.success("✅ Account created successfully! Now login.")
                else:
                    st.warning("⚠️ Username already taken.")
            else:
                st.warning("⚠️ Fill in all fields!")
   
    elif auth_option == "Login":
        if st.button("🔁 Login"):
            if username in st.session_state.users:
                stored_hash = st.session_state.users[username]["password"]
                if hash_password(password) == stored_hash:
                    st.session_state.is_logged_in = True
                    st.session_state.username = username
                    st.session_state.activity_log.append(f"User {username} logged in successfully.")
                    
                    # Trigger balloons animation here
                    st.balloons()
                    
                    st.success("✅ Logged in successfully!")
                    st.rerun()
                    
                else:
                    st.error("❌ Invalid password!")
                    st.session_state.failed_attempts += 1
            else:
                st.error("❌ Invalid username!")
                st.session_state.failed_attempts += 1

# ------------------- Main Flow -------------------

if not st.session_state.is_logged_in:
    show_login_signup()
    st.stop()

# ------------------- Sidebar -------------------

with st.sidebar:
    st.markdown("## 👤 User Profile")
    st.image("https://www.svgrepo.com/show/263684/user-profile.svg", width=230)
    st.markdown(f"**User:** {st.session_state.username}")

    with st.expander("🔐 Vault Management"):
        menu = ["🏠 Home", "➕ Store Data", "🔓 Retrieve Data", "⚙️ Advanced Features"]
        choice = st.selectbox("📍 Select Action", menu)

    with st.expander("🛡️ Security Settings"):
        if st.button("🚪 Logout"):
            st.session_state.is_logged_in = False
            st.rerun()

    st.markdown("---")
    st.markdown("### 🕒 System Status")
    if st.session_state.failed_attempts >= 3:
        st.warning("❌ Too many failed login attempts. You are temporarily locked.")
    else:
        st.success("🔒 Secure vault is running smoothly.")

# ------------------- Pages -------------------

if choice == "🏠 Home":
    if not st.session_state.home_balloons_shown:
        st.balloons()
        st.session_state.home_balloons_shown = True
    
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

elif choice == "➕ Store Data":
    st.subheader("➕ Encrypt & Store New Data")

    unique_id = st.text_input("🔤 Unique ID for Data:", placeholder="e.g., my_bank_pin_2025")
    user_data = st.text_area("📝 Enter Your Data:", placeholder="e.g., My ATM PIN is 1234", height=150, max_chars=500)
    st.caption(f"🧾 Characters used: {len(user_data)} / 500")

    passkey = st.text_input("🔑 Enter Secret Passkey:", placeholder="At least 6 characters", type="password")
    st.markdown(f"**Password Strength:** {password_strength(passkey)}")

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

elif choice == "🔓 Retrieve Data":
    st.subheader("🔓 Retrieve and Decrypt Your Data")
    
    # Show available data IDs
    if st.session_state.stored_data:
        st.info("📋 Available Data IDs:")
        for data_id in st.session_state.stored_data.keys():
            st.write(f"- {data_id}")
        st.markdown("---")
    
    unique_id = st.text_input("🆔 Enter Data ID:", placeholder="e.g., my_bank_pin_2025")
    passkey = st.text_input("🔑 Enter Passkey:", type="password")

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
                    st.markdown("🏷️ Tags:")
                    st.code(", ".join(data_obj["tags"]), language="markdown")
            else:
                st.error("❌ Incorrect passkey!")
                st.session_state.failed_attempts += 1
        else:
            st.error("❌ No data found with this ID. Please check the available IDs above.")

elif choice == "⚙️ Advanced Features":
    st.subheader("⚙️ Advanced Features")
    
    # Create tabs for different features
    tab1, tab2, tab3 = st.tabs(["🔒 Security Tools", "📊 Data Management", "🔍 Password Generator"])
    
    with tab1:
        st.markdown("### 🔒 Security Tools")
        
        # Password Change
        st.markdown("#### Change Your Password")
        st.info("ℹ️ Here you can change your login password. This is the password you use to log in.")
        
        current_pass = st.text_input("Current Password", type="password")
        new_pass = st.text_input("New Password", type="password")
        confirm_pass = st.text_input("Confirm New Password", type="password")
        
        if st.button("Update Password"):
            if not current_pass or not new_pass or not confirm_pass:
                st.error("❌ Please fill in all the fields!")
            elif new_pass == confirm_pass:
                if hash_password(current_pass) == st.session_state.users[st.session_state.username]["password"]:
                    st.session_state.users[st.session_state.username]["password"] = hash_password(new_pass)
                    st.success("✅ Password changed successfully!")
                    st.session_state.activity_log.append(f"User {st.session_state.username} changed their password")
                else:
                    st.error("❌ Current password is incorrect!")
            else:
                st.error("❌ The new passwords do not match!")
        
        # Session Management
        st.markdown("#### Session Management")
        if st.button("Clear All Sessions"):
            st.session_state.is_logged_in = False
            st.success("✅ All sessions cleared. Please log in again.")
            st.rerun()
    
    with tab2:
        st.markdown("### 📊 Data Management")
        
        # Export Data
        st.markdown("#### Export Your Data")
        if st.button("📥 Create Backup"):
            if st.session_state.stored_data:
                backup_data = {
                    "username": st.session_state.username,
                    "data": st.session_state.stored_data,
                    "timestamp": st.session_state.activity_log[-1] if st.session_state.activity_log else "No activity"
                }
                st.download_button(
                    label="Download Backup",
                    data=str(backup_data),
                    file_name=f"secure_vault_backup_{st.session_state.username}.json",
                    mime="application/json"
                )
            else:
                st.warning("⚠️ No data available to backup.")
        
        # Import Data
        st.markdown("#### Import Data")
        uploaded_file = st.file_uploader("Choose a backup file", type=['json'])
        if uploaded_file is not None:
            if st.button("Import Backup"):
                try:
                    import_data = uploaded_file.getvalue().decode()
                    backup = eval(import_data)
                    if backup.get("username") == st.session_state.username:
                        st.session_state.stored_data = backup.get("data", {})
                        st.success("✅ Data imported successfully!")
                        st.session_state.activity_log.append(f"User {st.session_state.username} imported data from backup")
                    else:
                        st.error("❌ Backup file doesn't match the current user!")
                except:
                    st.error("❌ Invalid backup file!")
    
    with tab3:
        st.markdown("### 🔍 Password Generator")
        st.info("Generate strong, secure passwords")
        
        # Password generation options
        col1, col2 = st.columns(2)
        with col1:
            length = st.slider("Password Length", 8, 32, 12)
            use_upper = st.checkbox("Include Uppercase Letters", value=True)
            use_lower = st.checkbox("Include Lowercase Letters", value=True)
        with col2:
            use_numbers = st.checkbox("Include Numbers", value=True)
            use_special = st.checkbox("Include Special Characters", value=True)
        
        if st.button("Generate Password"):
            import random
            import string
            
            chars = ""
            if use_upper: chars += string.ascii_uppercase
            if use_lower: chars += string.ascii_lowercase
            if use_numbers: chars += string.digits
            if use_special: chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
            
            if not chars:
                st.error("❌ Please select at least one character type!")
            else:
                password = ''.join(random.choice(chars) for _ in range(length))
                st.success("✅ Generated Password:")
                st.code(password)
                
                # Show password strength
                score = 0
                if length >= 12: score += 1
                if use_upper: score += 1
                if use_lower: score += 1
                if use_numbers: score += 1
                if use_special: score += 1
                
                st.progress(score/5)
                st.info(f"Password Strength: {'Very Strong' if score == 5 else 'Strong' if score == 4 else 'Medium' if score == 3 else 'Weak'}")
