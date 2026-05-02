import streamlit as st
import requests

API_URL = os.environ.get("SOC_API_URL", "http://localhost:8000")


def show_login_form():
    """Render the login form."""
    st.markdown("## 🔐 Login to AutonomousSOC")

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button(
            "Login", use_container_width=True, type="primary"
        )

        if submitted:
            if not username or not password:
                st.error("Please enter both username and password")
                return

            try:
                response = requests.post(
                    f"{API_URL}/login",
                    json={"username": username, "password": password},
                    timeout=10
                )

                if response.status_code == 200:
                    data = response.json()
                    # Store token and user info in session
                    st.session_state.token = data["access_token"]
                    st.session_state.username = data["username"]
                    st.session_state.role = data["role"]
                    st.session_state.logged_in = True
                    st.success(f"Welcome back {data['username']}!")
                    st.rerun()
                else:
                    error = response.json().get("detail", "Login failed")
                    st.error(f"Login failed: {error}")

            except requests.exceptions.ConnectionError:
                st.error("Cannot connect to API. Make sure server is running.")

def show_signup_form():
    """Render the signup form."""
    st.markdown("## 📝 Create Account")

    with st.form("signup_form"):
        col1, col2 = st.columns(2)
        with col1:
            first_name = st.text_input("First Name")
        with col2:
            last_name = st.text_input("Last Name")

        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input(
            "Password",
            type="password",
            help="Must be 8+ characters with uppercase, lowercase, number, and special character. Cannot contain your name."
        )
        confirm_password = st.text_input("Confirm Password", type="password")
        role = st.selectbox(
            "Role",
            options=["readonly", "analyst", "admin"],
            help="readonly=view only, analyst=analyze alerts, admin=full access"
        )

        # Show password requirements
        st.markdown("""
        **Password requirements:**
        - Minimum 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one number
        - At least one special character !@#$%^&*
        - Cannot contain your first or last name
        """)

        submitted = st.form_submit_button(
            "Create Account",
            use_container_width=True,
            type="primary"
        )

        if submitted:
            if not all([first_name, last_name, username, email,
                       password, confirm_password]):
                st.error("Please fill in all fields")
                return

            if password != confirm_password:
                st.error("Passwords do not match")
                return

            try:
                response = requests.post(
                    f"{API_URL}/signup",
                    json={
                        "username": username,
                        "first_name": first_name,
                        "last_name": last_name,
                        "email": email,
                        "password": password,
                        "role": role
                    },
                    timeout=10
                )

                if response.status_code == 200:
                    st.success("Account created successfully! Please login.")
                    st.session_state.show_signup = False
                    st.rerun()
                else:
                    error = response.json().get("detail", "Signup failed")
                    st.error(f"Error: {error}")

            except requests.exceptions.ConnectionError:
                st.error("Cannot connect to API.")


def show_auth_page():
    """
    Show login or signup page.
    Returns True if user is logged in.
    """
    # Already logged in
    if st.session_state.get("logged_in"):
        return True

    # Toggle between login and signup
    if "show_signup" not in st.session_state:
        st.session_state.show_signup = False

    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        if st.session_state.show_signup:
            show_signup_form()
            st.markdown("---")
            if st.button("Already have an account? Login",
                        use_container_width=True):
                st.session_state.show_signup = False
                st.rerun()
        else:
            show_login_form()
            st.markdown("---")
            if st.button("No account? Sign up",
                        use_container_width=True):
                st.session_state.show_signup = True
                st.rerun()

    return False


def logout():
    """Clear session and log out."""
    for key in ["token", "username", "role", "logged_in"]:
        if key in st.session_state:
            del st.session_state[key]
    st.rerun()


def get_auth_headers() -> dict:
    """Get headers with JWT token for API calls."""
    token = st.session_state.get("token", "")
    return {"Authorization": f"Bearer {token}"}