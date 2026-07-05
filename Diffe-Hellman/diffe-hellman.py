import streamlit as st
import os
import json
import sys
import time

# Name of the local parameter cache file
CONFIG_FILE = "dh_params.json"

# Set up page configuration for a modern, focused interface
st.set_page_config(
    page_title="Secure Portal - Diffie-Hellman & XOR",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)

def is_prime(n: int) -> bool:
    """
    Checks if a number is prime using trial division.
    Primes are positive integers greater than 1 with no divisors other than 1 and itself.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def encrypt_password(password: str, shared_key: int) -> list:
    """
    Encrypts a plaintext password using a simple bitwise XOR operation with the Shared Key.
    """
    encrypted = []
    for character in password:
        # XOR operation: character code point XOR shared_key
        encrypted.append(ord(character) ^ shared_key)
    return encrypted

def decrypt_password(encrypted_list: list, shared_key: int) -> str:
    """
    Decrypts an XOR-encrypted integer list back into a plaintext string.
    """
    decrypted = []
    for value in encrypted_list:
        # Reverse XOR operation using the identical shared key
        decrypted.append(chr(value ^ shared_key))
    return "".join(decrypted)

def get_terminal_inputs():
    """
    Checks for existing configuration. If none exists, pauses the execution
    and forces terminal input from the host user running the server.
    """
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except Exception:
            # If the file is corrupt, delete it and prompt again
            pass

    # Print out terminal configuration visual prompts
    print("\n" + "="*60)
    print("🔑  DIFFIE-HELLMAN KEY EXCHANGE - SECURE INITIALIZATION  🔑")
    print("="*60)
    print("Please configure the cryptographic key parameters in this terminal.")
    print("These parameters will be hidden from the web frontend.\n")

    # Input validation for Prime P
    while True:
        try:
            p_val = int(input("Enter Prime Number (P): "))
            if is_prime(p_val):
                break
            print("❌ Error: 'P' must be a prime number! Try again.")
        except ValueError:
            print("❌ Error: Please enter a valid integer.")

    # Input validation for Generator G
    while True:
        try:
            g_val = int(input("Enter Primitive Root / Generator (G): "))
            if g_val > 0:
                break
            print("❌ Error: Generator 'G' must be greater than 0.")
        except ValueError:
            print("❌ Error: Please enter a valid integer.")

    # Input Client Private Key
    while True:
        try:
            client_priv = int(input("Enter Client Private Key (a): "))
            if client_priv > 0:
                break
            print("❌ Error: Client Private key must be positive.")
        except ValueError:
            print("❌ Error: Please enter a valid integer.")

    # Input Server Private Key
    while True:
        try:
            server_priv = int(input("Enter Server Private Key (b): "))
            if server_priv > 0:
                break
            print("❌ Error: Server Private key must be positive.")
        except ValueError:
            print("❌ Error: Please enter a valid integer.")

    # Calculate keys
    client_pub = pow(g_val, client_priv, p_val)
    server_pub = pow(g_val, server_priv, p_val)
    
    client_shared = pow(server_pub, client_priv, p_val)
    server_shared = pow(client_pub, server_priv, p_val)

    if client_shared != server_shared:
        print("❌ Cryptographic Error: Computed shared keys do not match. Aborting.")
        sys.exit(1)

    shared_key = client_shared

    # Package setup payload
    params = {
        "p": p_val,
        "g": g_val,
        "client_private": client_priv,
        "server_private": server_priv,
        "client_public": client_pub,
        "server_public": server_pub,
        "shared_key": shared_key
    }

    # Save to disk so rerun doesn't trigger terminal prompt again
    with open(CONFIG_FILE, "w") as f:
        json.dump(params, f)

    print("\n✅ Cryptographic Setup Successful!")
    print(f"Computed Shared Key: {shared_key}")
    print("Frontend is now active. Refresh or open your browser tab.")
    print("="*60 + "\n")
    
    return params

# Read or request parameters via terminal
crypto_params = get_terminal_inputs()
shared_key = crypto_params["shared_key"]

# Initialize Streamlit simulated database
if "users" not in st.session_state:
    st.session_state.users = {}  # Format: {username: decrypted_password}

# Main Clean Interface Header
st.markdown("<h1 style='text-align: center;'>🔒 Secure Portal</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #888888;'>Powered by Diffie-Hellman Key Exchange & XOR Encryption</p>", unsafe_allow_html=True)
st.divider()

# Create standard Login and Register tabs on the UI
tab1, tab2 = st.tabs(["🔑 Sign In", "📝 Create Account"])

with tab2:
    st.subheader("Register New Account")
    st.caption("Your password will be encrypted using the active DH Shared Key before transmission.")
    
    reg_username = st.text_input("Choose Username", placeholder="e.g., alice_crypto", key="reg_user")
    reg_password = st.text_input("Choose Password", type="password", placeholder="Choose a strong password", key="reg_pass")
    
    register_button = st.button("Register Account", use_container_width=True)

    if register_button:
        if reg_username.strip() == "" or reg_password.strip() == "":
            st.error("⚠️ Username and password fields cannot be blank!")
        elif reg_username in st.session_state.users:
            st.warning("⚠️ This username is already registered.")
        else:
            # 1. Encrypt the registration password using the client side XOR Shared Key
            encrypted_reg_pass = encrypt_password(reg_password, shared_key)
            
            # 2. Simulate Server Decrypt and Database Storage
            decrypted_reg_pass = decrypt_password(encrypted_reg_pass, shared_key)
            st.session_state.users[reg_username] = decrypted_reg_pass
            
            st.toast("✨ Registration Successful! You can now log in.", icon="🎉")
            time.sleep(3)
            st.success("✨ **Registration Successful!**")
            
            # Log registration details in visual format
            st.info(f"🔑 **Client-Side Encrypted Output Sent:** {encrypted_reg_pass}")

with tab1:
    st.subheader("Login to Your Account")
    
    login_username = st.text_input("Username", placeholder="e.g., alice_crypto", key="login_user")
    login_password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_pass")
    
    login_button = st.button("Log In", use_container_width=True)

    if login_button:
        if login_username.strip() == "" or login_password.strip() == "":
            st.error("⚠️ Username and password fields cannot be blank!")
        else:
            # 1. Encrypt entered password with the Shared Key
            login_encrypted = encrypt_password(login_password, shared_key)
            
            # 2. Decrypt it to replicate validation checks
            login_decrypted = decrypt_password(login_encrypted, shared_key)
            
            # Display simulated visual telemetry logs
            st.markdown("#### Cryptographic Handshake Telemetry")
            col_l1, col_l2 = st.columns(2)
            with col_l1:
                st.write("**XOR Ciphertext Transmitted (Client)**")
                st.code(str(login_encrypted))
            with col_l2:
                st.write("**Decrypted Plaintext Verified (Server)**")
                st.code(login_decrypted)
            
            # 3. Perform database validation check
            if login_username in st.session_state.users:
                correct_password = st.session_state.users[login_username]
                if login_decrypted == correct_password:
                    st.toast(f"🔓 Login Successful! Welcome, {login_username}.", icon="🚀")
                    time.sleep(3)
                    st.success(f"🔓 **Login Successful!** Access granted to user '{login_username}'.")
                else:
                    st.error("❌ **Invalid Username or Password.** The credential check failed on the server.")
            else:
                st.error("❌ **Invalid Username or Password.** The credentials provided do not match any registered users.")

st.divider()

# Developer Expander containing active keys and values configured in the terminal
with st.expander("🛠️ Cryptographic Under-the-Hood Telemetry (Developer Panel)"):
    st.subheader("Active Key Exchange Architecture")
    st.markdown("""
    This debug console exposes the parameters configured **locally via the terminal script startup**.
    These values are invisible to external network clients.
    """)
    
    col_k1, col_k2 = st.columns(2)
    with col_k1:
        st.markdown("**Public Network Parameters**")
        st.write(f"- **Shared Prime (P):** `{crypto_params['p']}`")
        st.write(f"- **Generator (G):** `{crypto_params['g']}`")
        st.write(f"- **Client Public Key:** `{crypto_params['client_public']}`")
        st.write(f"- **Server Public Key:** `{crypto_params['server_public']}`")
        
    with col_k2:
        st.markdown("**Local Secret Space**")
        st.write(f"- **Client Private Key (a):** `[HIDDEN]`")
        st.write(f"- **Server Private Key (b):** `[HIDDEN]`")
        st.write(f"- **Established Shared Symmetric Key:** `{shared_key}`")
        
    st.subheader("Simulated Server Database")
    if st.session_state.users:
        st.json(st.session_state.users)
    else:
        st.info("No records are currently stored in the volatile database session state.")

    # Add parameters reset control
    st.subheader("Reset Configuration")
    if st.button("Delete Cache & Re-configure via Terminal"):
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)
        st.warning("⚠️ Configuration cleared! Please stop the server with Ctrl+C in your terminal and run 'streamlit run diffe-hellman.py' again to enter new parameters.")