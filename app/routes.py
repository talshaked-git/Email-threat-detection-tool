from flask import current_app as app, render_template
from app.email_analyzer import fetch_and_analyze_emails

@app.route('/')
def index():
    emails = fetch_and_analyze_emails()
    return render_template('index.html', emails=emails)
