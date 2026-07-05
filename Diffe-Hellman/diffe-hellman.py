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

def next_prime(n: int) -> int:
    """Finds the next prime number strictly greater than n."""
    n += 1
    while not is_prime(n):
        n += 1
    return n

def prev_prime(n: int) -> int:
    """Finds the largest prime number strictly less than n (min 2)."""
    if n <= 2:
        return 2
    n -= 1
    while n > 2 and not is_prime(n):
        n -= 1
    return n

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

def get_crypto_params():
    """
    Retrieves cryptographic parameters. If the config file exists, it is loaded.
    Otherwise, it renders a setup form in the Streamlit UI to configure them.
    """
    # 1. Check if already loaded in session state
    if "crypto_params" in st.session_state:
        return st.session_state.crypto_params

    # 2. Check if local cache file exists
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                params = json.load(f)
                st.session_state.crypto_params = params
                return params
        except Exception:
            pass

    # 3. If no config is found, render the UI Setup Form
    st.markdown("<h1 style='text-align: center;'>🔑 Diffie-Hellman Initial Setup</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #888888;'>Configure the public and private key parameters to initialize the secure portal.</p>", unsafe_allow_html=True)
    st.divider()

    st.warning("⚠️ **No configuration found.** Please configure the cryptographic parameters below to start the server. These parameters are used to establish the secure handshake.")

    if "p_val" not in st.session_state:
        st.session_state.p_val = 97
    if "g_val" not in st.session_state:
        st.session_state.g_val = 5
    if "client_priv" not in st.session_state:
        st.session_state.client_priv = 6
    if "server_priv" not in st.session_state:
        st.session_state.server_priv = 15

    col1, col2 = st.columns(2)
    with col1:
        # Shared Prime (P)
        st.markdown("**Shared Prime (P)**")
        col_dec, col_val, col_inc = st.columns([1, 2, 1])
        with col_dec:
            if st.button("➖", key="dec_p", use_container_width=True):
                st.session_state.p_val = prev_prime(st.session_state.p_val)
                st.rerun()
        with col_val:
            p_input = st.text_input("P Value", value=str(st.session_state.p_val), label_visibility="collapsed", key=f"p_input_field_{st.session_state.p_val}")
            try:
                p_input_int = int(p_input)
                if p_input_int != st.session_state.p_val:
                    st.session_state.p_val = p_input_int
                    st.rerun()
            except ValueError:
                pass
        with col_inc:
            if st.button("➕", key="inc_p", use_container_width=True):
                st.session_state.p_val = next_prime(st.session_state.p_val)
                st.rerun()

        p_is_prime = is_prime(st.session_state.p_val)
        if p_is_prime:
            st.success(f"✅ {st.session_state.p_val} is a prime number!")
        else:
            st.error(f"❌ {st.session_state.p_val} is NOT a prime number! Use ➕/➖ or enter a prime.")

        # Generator (G)
        st.markdown("**Generator/Base (G)**")
        col_dec, col_val, col_inc = st.columns([1, 2, 1])
        with col_dec:
            if st.button("➖", key="dec_g", use_container_width=True):
                st.session_state.g_val = max(1, st.session_state.g_val - 1)
                st.rerun()
        with col_val:
            g_input = st.text_input("G Value", value=str(st.session_state.g_val), label_visibility="collapsed", key=f"g_input_field_{st.session_state.g_val}")
            try:
                g_input_int = int(g_input)
                if g_input_int != st.session_state.g_val:
                    st.session_state.g_val = g_input_int
                    st.rerun()
            except ValueError:
                pass
        with col_inc:
            if st.button("➕", key="inc_g", use_container_width=True):
                st.session_state.g_val = st.session_state.g_val + 1
                st.rerun()

        g_is_valid = st.session_state.g_val > 0
        if not g_is_valid:
            st.error("❌ G must be a positive integer!")

    with col2:
        # Client Private Key (a)
        st.markdown("**Client Private Key (a)**")
        col_dec, col_val, col_inc = st.columns([1, 2, 1])
        with col_dec:
            if st.button("➖", key="dec_a", use_container_width=True):
                st.session_state.client_priv = max(1, st.session_state.client_priv - 1)
                st.rerun()
        with col_val:
            a_input = st.text_input("a Value", value=str(st.session_state.client_priv), label_visibility="collapsed", key=f"a_input_field_{st.session_state.client_priv}")
            try:
                a_input_int = int(a_input)
                if a_input_int != st.session_state.client_priv:
                    st.session_state.client_priv = a_input_int
                    st.rerun()
            except ValueError:
                pass
        with col_inc:
            if st.button("➕", key="inc_a", use_container_width=True):
                st.session_state.client_priv = st.session_state.client_priv + 1
                st.rerun()

        # Server Private Key (b)
        st.markdown("**Server Private Key (b)**")
        col_dec, col_val, col_inc = st.columns([1, 2, 1])
        with col_dec:
            if st.button("➖", key="dec_b", use_container_width=True):
                st.session_state.server_priv = max(1, st.session_state.server_priv - 1)
                st.rerun()
        with col_val:
            b_input = st.text_input("b Value", value=str(st.session_state.server_priv), label_visibility="collapsed", key=f"b_input_field_{st.session_state.server_priv}")
            try:
                b_input_int = int(b_input)
                if b_input_int != st.session_state.server_priv:
                    st.session_state.server_priv = b_input_int
                    st.rerun()
            except ValueError:
                pass
        with col_inc:
            if st.button("➕", key="inc_b", use_container_width=True):
                st.session_state.server_priv = st.session_state.server_priv + 1
                st.rerun()

    # Enable button only if P is prime and G is valid
    is_valid_setup = p_is_prime and g_is_valid

    submit = st.button("Initialize & Run Portal", use_container_width=True, disabled=not is_valid_setup)

    if submit:
        # Calculate public keys
        client_pub = pow(st.session_state.g_val, st.session_state.client_priv, st.session_state.p_val)
        server_pub = pow(st.session_state.g_val, st.session_state.server_priv, st.session_state.p_val)
        
        # Calculate shared secret
        client_shared = pow(server_pub, st.session_state.client_priv, st.session_state.p_val)
        server_shared = pow(client_pub, st.session_state.server_priv, st.session_state.p_val)

        if client_shared != server_shared:
            st.error("❌ Cryptographic Error: Computed shared keys do not match. Check your parameters.")
        else:
            params = {
                "p": st.session_state.p_val,
                "g": st.session_state.g_val,
                "client_private": st.session_state.client_priv,
                "server_private": st.session_state.server_priv,
                "client_public": client_pub,
                "server_public": server_pub,
                "shared_key": client_shared
            }
            
            # Try to write locally if possible
            try:
                with open(CONFIG_FILE, "w") as f:
                    json.dump(params, f)
            except Exception:
                pass # Ignore write errors if running in read-only environment
            
            st.session_state.crypto_params = params
            st.success("✅ Setup Successful! Loading Portal...")
            st.rerun()

    st.stop() # Halt execution until parameters are configured

# Read or request parameters
crypto_params = get_crypto_params()
shared_key = crypto_params["shared_key"]

# Initialize Streamlit simulated database and session state
if "users" not in st.session_state:
    st.session_state.users = {}  # Format: {username: decrypted_password}

if "logged_in" not in st.session_state:
    st.session_state.logged_in = None

if "login_telemetry" not in st.session_state:
    st.session_state.login_telemetry = None

# Main Clean Interface Header
st.markdown("<h1 style='text-align: center;'>🔒 Secure Portal</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #888888;'>Powered by Diffie-Hellman Key Exchange & XOR Encryption</p>", unsafe_allow_html=True)
st.divider()

# Render tabs conditionally based on login state
if st.session_state.logged_in:
    tab1, tab2 = st.tabs(["🏠 Dashboard", "📖 Documentation"])
    
    with tab1:
        st.subheader(f"Welcome back, {st.session_state.logged_in}! 👋")
        st.success(f"🔓 **Access Granted.** You are authenticated securely using Diffie-Hellman & XOR.")
        
        # Display telemetry if available from the login/registration action
        if st.session_state.login_telemetry:
            st.markdown("#### Handshake Telemetry")
            col_l1, col_l2 = st.columns(2)
            with col_l1:
                st.write("**XOR Ciphertext Transmitted (Client)**")
                st.code(str(st.session_state.login_telemetry["ciphertext"]))
            with col_l2:
                st.write("**Decrypted Plaintext Verified (Server)**")
                st.code(st.session_state.login_telemetry["plaintext"])
        
        st.divider()
        if st.button("🚪 Log Out", use_container_width=True):
            st.session_state.logged_in = None
            st.session_state.login_telemetry = None
            st.toast("Logged out successfully!", icon="ℹ️")
            time.sleep(1)
            st.rerun()

    with tab2:
        st.subheader("📚 Cryptographic Foundation: Diffie-Hellman & XOR")
        st.markdown("""
        This application demonstrates secure communication by establishing a shared secret over an untrusted channel using **Diffie-Hellman Key Exchange (DHKE)**, then using that secret for **Symmetric XOR Encryption**.
        """)
        
        st.markdown("### 🔑 1. The Diffie-Hellman Protocol")
        st.markdown("""
        The Diffie-Hellman key exchange algorithm allows two parties (Client and Server) to generate a shared secret key that only they know, even if an eavesdropper is listening to all their communication.
        """)
        
        st.info("💡 **Did you know?** DHKE is not used to encrypt the messages themselves; rather, it is used to safely agree on a shared symmetric key, which is then used by a symmetric cipher (like XOR in this demo, or AES in real-world protocols) to encrypt/decrypt messages.")
        
        st.markdown("#### ⚙️ The Mathematical Steps:")
        
        st.markdown("**Step 1: Global Public Parameters**")
        st.markdown("Both parties agree on a large prime number $P$ and a generator $G$ (a primitive root modulo $P$). These are public and can be known by anyone.")
        st.latex(r"P \quad (\text{Prime}), \quad G \quad (\text{Generator})")
        
        st.markdown("**Step 2: Private Exponents (Secrets)**")
        st.markdown("- **Client** chooses a secret private key $a$.")
        st.markdown("- **Server** chooses a secret private key $b$.")
        st.markdown("These private keys are never transmitted or shared.")
        
        st.markdown("**Step 3: Compute Public Keys**")
        st.markdown("Both parties compute their public keys and exchange them:")
        st.latex(r"\text{Client Public Key: } A = G^a \pmod P")
        st.latex(r"\text{Server Public Key: } B = G^b \pmod P")
        
        st.markdown("**Step 4: Compute the Shared Secret**")
        st.markdown("Each party computes the shared secret key using the other party's public key and their own private key:")
        st.markdown("- **Client** computes: $S_{\text{client}} = B^a \pmod P$")
        st.markdown("- **Server** computes: $S_{\text{server}} = A^b \pmod P$")
        
        st.markdown("#### 🤝 Why does the math work?")
        st.markdown("Because of modular exponentiation rules, both computations yield the exact same result:")
        st.latex(r"S = (G^b)^a \equiv (G^a)^b \equiv G^{ab} \pmod P")
        
        st.divider()
        
        st.markdown("### 🔒 2. XOR Symmetric Encryption")
        st.markdown("""
        Once the shared key $S$ is established, it is used as the key for encryption. In this app, we use a classic **XOR (Exclusive OR) Cipher**.
        
        An XOR cipher operates on the binary representations of the plaintext and the key:
        """)
        st.latex(r"\text{Encryption: } C_i = P_i \oplus S")
        st.latex(r"\text{Decryption: } P_i = C_i \oplus S")
        st.markdown("""
        Where:
        - $P_i$ is the character code point of the plaintext character.
        - $C_i$ is the encrypted integer value.
        - $S$ is the Shared Symmetric Key.
        - $\\oplus$ is the bitwise XOR operation.
        
        #### 🛡️ Properties of XOR Encryption:
        - **Self-Inverse**: Applying the XOR operation twice with the same key restores the original value: $(P_i \\oplus S) \\oplus S = P_i$. This is why the same function is used to both encrypt and decrypt.
        - **Symmetric**: Both client and server must possess the exact same key $S$ to communicate.
        """)

else:
    tab1, tab2, tab3 = st.tabs(["🔑 Sign In", "📝 Create Account", "📖 Documentation"])
    
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
                st.success("✨ **Registration Successful!** You can now switch to the 'Sign In' tab and log in.")
    
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
                
                # 3. Perform database validation check
                if login_username in st.session_state.users:
                    correct_password = st.session_state.users[login_username]
                    if login_decrypted == correct_password:
                        st.session_state.logged_in = login_username
                        st.session_state.login_telemetry = {
                            "ciphertext": login_encrypted,
                            "plaintext": login_decrypted
                        }
                        st.toast(f"🔓 Login Successful! Welcome, {login_username}.", icon="🚀")
                        time.sleep(1.5)
                        st.rerun()
                    else:
                        st.error("❌ Incorrect password.")
                else:
                    st.error("❌ Username does not exist.")
    
    with tab3:
        st.subheader("📚 Cryptographic Foundation: Diffie-Hellman & XOR")
        st.markdown("""
        This application demonstrates secure communication by establishing a shared secret over an untrusted channel using **Diffie-Hellman Key Exchange (DHKE)**, then using that secret for **Symmetric XOR Encryption**.
        """)
        
        st.markdown("### 🔑 1. The Diffie-Hellman Protocol")
        st.markdown("""
        The Diffie-Hellman key exchange algorithm allows two parties (Client and Server) to generate a shared secret key that only they know, even if an eavesdropper is listening to all their communication.
        """)
        
        st.info("💡 **Did you know?** DHKE is not used to encrypt the messages themselves; rather, it is used to safely agree on a shared symmetric key, which is then used by a symmetric cipher (like XOR in this demo, or AES in real-world protocols) to encrypt/decrypt messages.")
        
        st.markdown("#### ⚙️ The Mathematical Steps:")
        
        st.markdown("**Step 1: Global Public Parameters**")
        st.markdown("Both parties agree on a large prime number $P$ and a generator $G$ (a primitive root modulo $P$). These are public and can be known by anyone.")
        st.latex(r"P \quad (\text{Prime}), \quad G \quad (\text{Generator})")
        
        st.markdown("**Step 2: Private Exponents (Secrets)**")
        st.markdown("- **Client** chooses a secret private key $a$.")
        st.markdown("- **Server** chooses a secret private key $b$.")
        st.markdown("These private keys are never transmitted or shared.")
        
        st.markdown("**Step 3: Compute Public Keys**")
        st.markdown("Both parties compute their public keys and exchange them:")
        st.latex(r"\text{Client Public Key: } A = G^a \pmod P")
        st.latex(r"\text{Server Public Key: } B = G^b \pmod P")
        
        st.markdown("**Step 4: Compute the Shared Secret**")
        st.markdown("Each party computes the shared secret key using the other party's public key and their own private key:")
        st.markdown("- **Client** computes: $S_{\text{client}} = B^a \pmod P$")
        st.markdown("- **Server** computes: $S_{\text{server}} = A^b \pmod P$")
        
        st.markdown("#### 🤝 Why does the math work?")
        st.markdown("Because of modular exponentiation rules, both computations yield the exact same result:")
        st.latex(r"S = (G^b)^a \equiv (G^a)^b \equiv G^{ab} \pmod P")
        
        st.divider()
        
        st.markdown("### 🔒 2. XOR Symmetric Encryption")
        st.markdown("""
        Once the shared key $S$ is established, it is used as the key for encryption. In this app, we use a classic **XOR (Exclusive OR) Cipher**.
        
        An XOR cipher operates on the binary representations of the plaintext and the key:
        """)
        st.latex(r"\text{Encryption: } C_i = P_i \oplus S")
        st.latex(r"\text{Decryption: } P_i = C_i \oplus S")
        st.markdown("""
        Where:
        - $P_i$ is the character code point of the plaintext character.
        - $C_i$ is the encrypted integer value.
        - $S$ is the Shared Symmetric Key.
        - $\\oplus$ is the bitwise XOR operation.
        
        #### 🛡️ Properties of XOR Encryption:
        - **Self-Inverse**: Applying the XOR operation twice with the same key restores the original value: $(P_i \\oplus S) \\oplus S = P_i$. This is why the same function is used to both encrypt and decrypt.
        - **Symmetric**: Both client and server must possess the exact same key $S$ to communicate.
        """)

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
    if st.button("Reset & Re-configure Parameters", use_container_width=True):
        if os.path.exists(CONFIG_FILE):
            try:
                os.remove(CONFIG_FILE)
            except Exception:
                pass
        if "crypto_params" in st.session_state:
            del st.session_state.crypto_params
        st.toast("Configuration cleared! Refreshing setup...", icon="🔄")
        time.sleep(1)
        st.rerun()