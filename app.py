from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_caching import Cache
from flask_compress import Compress
from flask_session import Session
import firebase_admin
from firebase_admin import credentials, auth, db
from dotenv import load_dotenv
from time import sleep
from datetime import datetime
import os
import threading
import re
import requests
import json

# 🔹 Load environment variables
load_dotenv()

# 🔹 Flask App Initialization
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "innovation_is_the_key")

# 🔥 Enable Flask-Caching (Speeds up template loading)
app.config['CACHE_TYPE'] = 'simple'
app.config['CACHE_DEFAULT_TIMEOUT'] = 120
cache = Cache(app)

# 🔥 Enable Compression (Gzip for static files)
Compress(app)

# 🔥 Enable Server-Side Sessions (Safer than client-side sessions)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_PERMANENT'] = False
Session(app)

# 🔥 Initialize Firebase with Realtime Database
cred = credentials.Certificate("sigma-accountcreation-firebase-adminsdk-fbsvc-02cd452ff0.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': "https://sigma-accountcreation-default-rtdb.firebaseio.com/"
})
print("✅ Firebase Realtime Database has been initialized!")

# Initialize Flask Web API
FIREBASE_WEB_API_KEY = "THIS_KEY_HAS_BEEN_REVOKED"
print("Firebase Authentication WEB API initialized!")

# ✅ Stronger Password Validation
def is_valid_password(password):
    return bool(re.fullmatch(r'^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=]).{8,}$', password))

# ✅ Stronger Email Validation
def is_valid_email(email):
    return bool(re.fullmatch(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email))

# ✅ Function to Get User's Country from IP
def get_user_country():
    try:
        response = requests.get("http://ip-api.com/json/")
        data = response.json()
        return data.get("country", "Unknown")
    except Exception as e:
        print(f"❌ Error getting country: {e}")
        return "Unknown"

# 🔹 Home Route (Cached for Faster Loading)
@app.route('/')
@cache.cached(timeout=120)
def home():
    flash("The website is in the TESTING phase. If any bugs are to be found, kindly report them at the following email address: avaaneesh2011@gmail.com. ", "info")
    return render_template('home.html')

# 🔹 User Signup
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        password = request.form['password']
        repassword = request.form['re_password']

        if password != repassword:
            flash("Passwords do not match.", "error")
            return redirect(url_for('signup'))

        if not is_valid_password(password):
            flash("Weak password. Use at least 8 chars with uppercase, number, and symbol.", "error")
            return redirect(url_for('signup'))
        
        if not is_valid_email(email):
            flash("Invalid email format.", "error")
            return redirect(url_for('signup'))

        def async_create_user():
            try:
                user = auth.create_user(email=email, password=password)
                user_ref = db.reference(f'Users/{user.uid}')
                user_ref.set({'FirstName': first_name, 'LastName': last_name, 'Email': email, 'Password': password})
                print(f"✅ User {email} with {password} created successfully in Realtime Database!")
            except Exception as e:
                print(f"❌ Signup Error: {e}")

        # ✅ Offload Firebase user creation to a background thread
        threading.Thread(target=async_create_user).start()
        flash("Signup successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # 🔥 Authenticate using Firebase REST API
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        response = requests.post(url, json=payload)
        result = response.json()

        if "idToken" in result:
            user_uid = result["localId"]
            session.clear()
            session['user'] = {'uid': user_uid, 'email': email}
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash(f"Login Error: {result.get('error', {}).get('message', 'Unknown error')}", "error")

    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        flash("Please log in.", "error")
        return redirect(url_for("home"))
    
    return render_template('dashboard.html', email=session['user']['email'])

# 🔹 Update User Profile (Async Firestore Update)
@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user' not in session:
        return jsonify({"message": "Unauthorized access. Please log in."}), 403

    data = request.get_json()
    user_uid = session['user']['uid']

    def async_update_profile():
        try:
            user_ref = db.reference(f'Users/{user_uid}')
            user_ref.update(data)
            print("✅ Profile updated successfully!")
        except Exception as e:
            print(f"❌ Error updating profile: {e}")

    # ✅ Offload profile update to a background thread
    threading.Thread(target=async_update_profile).start()

    return jsonify({"message": "Profile update is processing in the background!"}), 202

# 🔹 Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('home'))

@app.route('/checkout-8asc93029fniencow92i23n93n290293n3-29393988283993269727')
def checkout_pro():
    return render_template('checkout_page_pro.html')

@app.route('/checkout-98f09fh034hf0hfn3j8h490jdjd90j30jd-90i29039239384292998')
def checkout_max():
    return render_template('checkout_page_max.html')

@app.route('/donate')
def donate():
    return render_template('donate.html')

# 🔹 Password Reset
@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']

        # 🔥 Firebase API for password reset
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key={FIREBASE_WEB_API_KEY}"
        payload = {
            "requestType": "PASSWORD_RESET",
            "email": email
        }

        response = requests.post(url, json=payload)
        result = response.json()

        if "error" in result:
            flash("Error: " + result["error"]["message"], "error")
        else:
            flash("Password reset link sent! Check your email.", "success")

    return render_template('externel/password_reset_form.html')

@app.route('/update_password', methods=['GET', 'POST'])
def update_password():
    oob_code = request.args.get('oobCode')  # Get Firebase verification code

    if request.method == 'POST':
        new_password = request.form['new_password']

        # 🔥 Firebase API to confirm password reset
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:resetPassword?key={FIREBASE_WEB_API_KEY}"
        payload = {
            "oobCode": oob_code,
            "newPassword": new_password
        }

        response = requests.post(url, json=payload)
        result = response.json()

        if "error" in result:
            flash("Error: " + result["error"]["message"], "error")
        else:
            flash("Password has been reset successfully! You can now log in.", "success")
            return redirect(url_for('login'))

    return render_template('externel/password_update_form.html', oob_code=oob_code)


# 🔹 Additional Routes
@app.route('/activity01_investment_strategies')
@cache.cached(timeout=600)
def activity01():
    if 'user' not in session:
        flash("Please log in.", "error")
        return render_template("err405.html")
    return render_template('activity01_investment_strategies.html', email=session['user']['email'])

@app.route('/subscriptions')
def subscriptions():
    return render_template('subscriptions.html')

@app.route('/about_us')
def about_us():
    return render_template('about_us.html')

# 🔹 Blog Posts

@app.route('/blog_post_how_to_invest_like_a_pro')
def blog_post_invest_like_a_pro():
    return render_template('blogs/blog_post_how_to_invest_like_a_pro.html')

# 🔹 FinanceGPT
@app.route('/finance_gpt')
def finance_gpt():
    return render_template('finance_gpt.html')

# 🔹 Login Route (Handles the HTML Form Submission)
@app.route('/financegpt_login', methods=['GET', 'POST'])
def financegpt_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # 🔥 Authenticate using Firebase REST API
        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={FIREBASE_WEB_API_KEY}"
        payload = {
            "email": email,
            "password": password,
            "returnSecureToken": True
        }
        response = requests.post(url, json=payload)
        result = response.json()

        print("🔥 Firebase Response:", json.dumps(result, indent=4))  # Debugging

        if "idToken" in result:
            # ✅ User Exists, Save Session & Redirect
            user_uid = result["localId"]
            session['user'] = {'uid': user_uid, 'email': email}

            # 📍 Store Login Timestamp & Country
            timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
            country = get_user_country()

            # 🔥 Update Firebase Realtime Database
            user_ref = db.reference(f'Users/{user_uid}/Logins')
            new_login_ref = user_ref.push()
            new_login_ref.set({
                "timestamp": timestamp,
                "country": country
            })

            flash("Login successful!", "success")
            return redirect(url_for('finance_gpt_download'))
        else:
            # ❌ Login Failed, Show Error Message
            error_message = result.get("error", {}).get("message", "Invalid credentials. Please try again.")
            flash(f"Login Failed: {error_message}", "error")

    return render_template('finance_gpt_login.html')

@app.route('/finance_gpt_download')
def finance_gpt_download():
    if 'user' not in session:
        flash("Unauthorized access. Please log in.", "error")
        return redirect(url_for('financegpt_login'))
    
    return render_template('finance_gpt_download.html')

@app.route('/gpt_android')
def gpt_android():
    try:
        return send_from_directory(directory='static/app_download', path='FinanceGPT.apk', as_attachment=True)
    except Exception as e:
        flash(f"Error downloading file: {str(e)}", "error")
        return redirect(url_for('finance_gpt_download'))

@app.route('/download_activity01_video')
def download_activity01_video():
    try:
        return send_from_directory(directory='static/videos', path='FinancesBasic360p.mp4', as_attachment=True)
    except Exception as e:
        flash(f"Error downloading file: {str(e)}", "error")
        return redirect(url_for('dashboard'))

@app.route('/course_certificate_crash_course')
def course_certificate_crash_course():
    try:
        return send_from_directory(directory='static/images', path='CourseCompletionCertificate.png', as_attachment=True)
    except Exception as e:
        flash(f"Error downloading certificate: {str(e)}", "error")
        return redirect(url_for('dashboard'))

# 🔹 Loan Calculator Page (Cached)
@app.route("/loan_calculator")
@cache.cached(timeout=600)
def loan_calculator():
    return render_template('calculators/loan_calculator.html')

# <-- Direct Classes -->
@app.route('/home_direct')
def home_direct():
    return render_template('home_direct.html')

@app.route("/location_direct")
def location_direct():
    return render_template('location_direct.html')

@app.route("/schedule_direct")
def schedule_direct():
    return render_template('schedule_direct.html')

# 🔹 Run Flask App
if __name__ == '__main__':
    print("Running Flask Testing Server!")
    print("Priming thread for 5 seconds..")
    sleep(5)
    print("Rendering Flask Testing Server...")
    app.run(host="0.0.0.0", port=5000)
