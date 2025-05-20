import re
import sqlite3
import contextlib
from datetime import timedelta
import time, random, os, tempfile, zipfile
from datetime import datetime, timedelta
from faker import Faker
import pandas as pd
import requests

import undetected_chromedriver as uc
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import (
    Flask, render_template, 
    request, session, redirect
)

from create_database import setup_database
from utils import login_required, set_session





app = Flask(__name__)

app.config['SECRET_KEY'] = 'EXAMPLE_xpSm7p5bgJY8rNoBjGWiz5yjxMNlW6231IBI62OkLc='
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=15)

setup_database(name='users.db')

DEVICE_PROFILES = [
    {
        "name": "Apple iPhone 13",
        "user_agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
        "resolution": "390x844"
    },
    {
        "name": "iPad Pro",
        "user_agent": "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
        "resolution": "1024x1366"
    },
    {
        "name": "Samsung Galaxy S21",
        "user_agent": "Mozilla/5.0 (Linux; Android 11; SAMSUNG SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36",
        "resolution": "360x800"
    },
    {
        "name": "Dell XPS 15 (Windows)",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
        "resolution": "1920x1200"
    },
    {
        "name": "Lenovo ThinkPad (Linux)",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.36",
        "resolution": "1366x768"
    },
    {
        "name": "MacBook Pro",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_0) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0 Safari/605.1.15",
        "resolution": "1440x900"
    }
]

# ==== Generate DOB ====
def generate_random_dob(start_year=1960, end_year=2005):
    start_date = datetime(start_year, 1, 1)
    end_date = datetime(end_year, 12, 31)
    random_days = random.randint(0, (end_date - start_date).days)
    return (start_date + timedelta(days=random_days)).strftime("%Y-%m-%d")

# ==== Create Proxy Extension ====
def create_proxy_extension(proxy_host, proxy_port, proxy_user, proxy_pass):
    manifest_json = """
    {
        "version": "1.0.0",
        "manifest_version": 2,
        "name": "Chrome Proxy",
        "permissions": [
            "proxy",
            "tabs",
            "unlimitedStorage",
            "storage",
            "<all_urls>",
            "webRequest",
            "webRequestBlocking"
        ],
        "background": {
            "scripts": ["background.js"]
        }
    }
    """

    background_js = f"""
    var config = {{
        mode: "fixed_servers",
        rules: {{
            singleProxy: {{
                scheme: "http",
                host: "{proxy_host}",
                port: parseInt({proxy_port})
            }},
            bypassList: ["localhost"]
        }}
    }};

    chrome.proxy.settings.set({{value: config, scope: "regular"}}, function() {{}});

    chrome.webRequest.onAuthRequired.addListener(
        function(details) {{
            return {{
                authCredentials: {{
                    username: "{proxy_user}",
                    password: "{proxy_pass}"
                }}
            }};
        }},
        {{urls: ["<all_urls>"]}},
        ["blocking"]
    );
    """

    pluginfile = tempfile.mktemp(suffix='.zip')
    with zipfile.ZipFile(pluginfile, 'w') as zp:
        zp.writestr("manifest.json", manifest_json)
        zp.writestr("background.js", background_js)

    return pluginfile

# ==== Create Chrome Driver ====
def create_driver_with_device(user_index):
    profile = random.choice(DEVICE_PROFILES)
    proxy_host = "au.decodo.com"
    proxy_user = "sp7xq17fwm"
    proxy_pass = "3hFpvxOv1qf75fVCq+"
    proxy_port = 30001 + user_index

    extension = create_proxy_extension(proxy_host, proxy_port, proxy_user, proxy_pass)

    options = uc.ChromeOptions()
    options.add_argument(f"user-agent={profile['user_agent']}")
    options.add_argument(f"--window-size={profile['resolution']}")
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    options.add_argument('--headless=new')
    options.add_argument('--mute-audio')
    options.add_extension(extension)

    return uc.Chrome(options=options, headless=True)

# ==== Fill the Form ====
def fill_form(driver, user_data):
    driver.get("https://firstchoicequotes.info/")
    WebDriverWait(driver, 30).until(EC.presence_of_element_located((By.ID, "fname")))

    driver.find_element(By.ID, "fname").send_keys(user_data['fname'])
    driver.find_element(By.ID, "lname").send_keys(user_data['lname'])
    driver.find_element(By.ID, "dob").send_keys(user_data['dob'])
    driver.find_element(By.ID, "phoneNo").send_keys(user_data['phoneNo'])
    driver.find_element(By.ID, "state").send_keys(user_data['state'])
    driver.find_element(By.ID, "zipcode").send_keys(user_data['zipcode'])

    checkbox = driver.find_element(By.ID, "consent")
    if not checkbox.is_selected():
        driver.execute_script("arguments[0].click();", checkbox)

    submit = driver.find_element(By.ID, "submit")
    driver.execute_script("arguments[0].scrollIntoView(true);", submit)
    time.sleep(0.5)
    driver.execute_script("arguments[0].click();", submit)
    time.sleep(3)
fake = Faker()
def _ip():
    country_codes = ['US', 'CA', 'GB', 'IN', 'AU', 'DE', 'FR', 'BR', 'ZA', 'JP']
    country_code = random.choice(country_codes)
    
    ip_parts = [random.randint(0, 255) for _ in range(4)]
    ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{ip_parts[3]}"
    
    country = fake.country_code() 
    return ip, country
# ==== Save Data to Excel ====
def save_user_data_to_csv(user_data, filename="form_submissions.csv"):
    user_data['website'] = "https://firstchoicequotes.info/"
    user_data['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_data['lead_id'] = f"LEAD-{random.randint(100000, 999999)}"
    
    ip, country = _ip()
    user_data['ip_address'] = ip
    
    field_order = [
        'lead_id', 'fname', 'lname', 'website', 'ip_address', 
        'zipcode', 'dob', 'state', 'timestamp'
    ]

    df_new = pd.DataFrame([user_data], columns=field_order)

    if os.path.exists(filename):
        df_existing = pd.read_csv(filename)
        df_combined = pd.concat([df_existing, df_new], ignore_index=True)
    else:
        df_combined = df_new

    df_combined.to_csv(filename, index=False)


@app.route('/form')
@login_required
def index():
    print(f'User data: {session}')
    return render_template('index.html', username=session.get('username'))


@app.route('/submit', methods=['POST'])
@login_required
def submit():
    try:
        user_data = {
            'fname': request.form['fname'],
            'lname': request.form['lname'],
            'dob': request.form['dob'] or generate_random_dob(),
            'phoneNo': request.form['phoneNo'],
            'state': request.form['state'],
            'zipcode': request.form['zipcode']
        }

        driver = create_driver_with_device(0)
        fill_form(driver, user_data)
        driver.quit()
        save_user_data_to_csv(user_data)
        message = f"✅ Form submitted successfully for {user_data['fname']}!"
    except Exception as e:
        message = f"❌ Error occurred: {str(e)}"

    return render_template('index.html', message=message)  # Pass the message to the template

@app.route('/logout')
def logout():
    session.clear()
    session.permanent = False
    return redirect('/login')

@app.route('/')
def main_page():
     return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    # Set data to variables
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Attempt to query associated user data
    query = 'select username, password, email from users where username = :username;'

    with contextlib.closing(sqlite3.connect('users.db')) as conn:
        with conn:
            account = conn.execute(query, {'username': username}).fetchone()

    if not account: 
        return render_template('login.html', error='Username does not exist')

    # Verify password
    try:
        ph = PasswordHasher()
        ph.verify(account[1], password)
    except VerifyMismatchError:
        return render_template('login.html', error='Incorrect password')

    # Check if password hash needs to be updated
    if ph.check_needs_rehash(account[1]):
        query = 'update set password = :password where username = :username;'
        params = {'password': ph.hash(password), 'username': account[0]}

        with contextlib.closing(sqlite3.connect('users.db')) as conn:
            with conn:
                conn.execute(query, params)

    # Set cookie for user session
    set_session(
        username=account[0], 
        remember_me='remember-me' in request.form
    )
    
    return redirect('/form')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    
    # Store data to variables 
    password = request.form.get('password')
    confirm_password = request.form.get('confirm-password')
    username = request.form.get('username')
    email = request.form.get('email')

    # Verify data
    if len(password) < 8:
        return render_template('register.html', error='Your password must be 8 or more characters')
    if password != confirm_password:
        return render_template('register.html', error='Passwords do not match')
    if not re.match(r'^[a-zA-Z0-9]+$', username):
        return render_template('register.html', error='Username must only be letters and numbers')
    if not 3 < len(username) < 26:
        return render_template('register.html', error='Username must be between 4 and 25 characters')

    query = 'select username from users where username = :username;'
    with contextlib.closing(sqlite3.connect('users.db')) as conn:
        with conn:
            result = conn.execute(query, {'username': username}).fetchone()
    if result:
        return render_template('register.html', error='Username already exists')

    # Create password hash
    pw = PasswordHasher()
    hashed_password = pw.hash(password)

    query = 'insert into users(username, password, email) values (:username, :password, :email);'
    params = {
        'username': username,
        'password': hashed_password,
        'email': email
    }

    with contextlib.closing(sqlite3.connect('users.db')) as conn:
        with conn:
            result = conn.execute(query, params)

    # We can log the user in right away since no email verification
    set_session(username=username)
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
