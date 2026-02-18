from flask import Flask , render_template, request, redirect, session, flash
from flask_bcrypt import Bcrypt
import sqlite3
import re

def is_strong_password(password):
    regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*]).{8,}$"
    if re.match(regex, password):
        return True
    return False

def role_required(allowed_roles):
    def decorator(func):
        def wrapper(*args, **kwargs):
            if "role" not in session:
                return redirect("/login")
            if session["role"] not in allowed_roles:
                return "<h1>Access Denied: Your role does not have permission.</h1>" \
                "<a href='/dashboard'>Back to Dashboard</a>"
            return func(*args, **kwargs)
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator

app = Flask(__name__)
app.secret_key = "your_secret_key_here"
bcrypt = Bcrypt(app)

@app.route("/register", methods=["GET", "POST"])
def register():    
    if request.method =="POST":     
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = sqlite3.connect("database.db")
        c = conn.cursor()

        if not is_strong_password(password):
            flash("Password must contain at least one uppercase letter, one lowercase letter, one number, one special character, and be at least 8 characters long.", "error")
            return redirect('/register')
        
        try:
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                      (username, hashed_password, role))
            c.execute("INSERT INTO logs (user_id, action, target_type, target_id) VALUES (?, ?, ?, ?)",
                    (c.lastrowid, "Created User", "user", c.lastrowid))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists.", "error")
            return redirect('/register')
        finally:
            conn.close()

        return redirect("/login")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()        

        if user and bcrypt.check_password_hash(user[2], password):
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["role"] = user[3]

            c.execute("INSERT INTO logs (user_id, action, target_type, target_id) VALUES (?, ?, ?, ?)",
                    (session["user_id"], "Logged In", "user", session["user_id"]))
            conn.commit()
            conn.close()
            return redirect("/dashboard")
        else:
            flash("Invalid username or password.", "error")
            return redirect('/login')
        
    return render_template("login.html")

@app.route("/dashboard")
@role_required(["user", "manager", "admin"])
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("dashboard.html")

@app.route("/logout")
def logout():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    c.execute("INSERT INTO logs (user_id, action, target_type, target_id) VALUES (?, ?, ?, ?)",
                    (session["user_id"], "Logged Out", "user", session["user_id"]))
    conn.commit()
    conn.close()

    session.clear()
    return redirect("/login")

@app.route("/admin")
@role_required(["admin"])
def admin_panel():
    return "<h1>Admin Panel - Only Admins Can See This</h1>" \
    "<a href='/dashboard'>Back to Dashboard</a>"

@app.route("/create_task", methods=["GET", "POST"])
@role_required(["user","admin","manager"])
def create_task():
    if request.method == "POST":
        title = request.form["title"]
        description = request.form["description"]
        assigned_to = request.form.get("assigned_to")
        if assigned_to == "":
            assigned_to = None

        conn = sqlite3.connect("database.db")
        c = conn.cursor()
        c.execute("INSERT INTO tasks (title, description, status, created_by, assigned_to) VALUES (?, ?, ?, ?, ?)",
                 (title, description, "Pending", session["user_id"], assigned_to))
        c.execute("INSERT INTO logs (user_id, action, target_type, target_id) VALUES (?, ?, ?, ?)",
                  (session["user_id"], "Created Task", "task", c.lastrowid))
        conn.commit()
        conn.close()
        flash("Task created successfully!", "success")
        return redirect("/create_task")
    return render_template("create_task.html")

# @app.route("/tasks")
# @role_required(["user", "manager", "admin"])
# def tasks():
#     conn = sqlite3.connect("database.db")
#     c = conn.cursor()

#     if session["role"] == "user":
#         c.execute("SELECT * FROM tasks WHERE assigned_to=? OR created_by=?", 
#                   (session["user_id"], session["user_id"],))
#     elif session["role"] == "manager":
#         c.execute("SELECT * FROM tasks")
#     else:
#         c.execute("SELECT * FROM tasks")

#     tasks_list = c.fetchall()
#     conn.close()
#     return render_template("tasks.html", tasks=tasks_list)

@app.route("/tasks")
@role_required(["user", "manager", "admin"])
def tasks():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    # Pagination setup
    page = request.args.get("page", 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    if session["role"] == "user":
        c.execute("SELECT COUNT(*) FROM tasks WHERE assigned_to=? OR created_by=?", 
                  (session["user_id"], session["user_id"],))
        total = c.fetchone()[0]

        c.execute("SELECT * FROM tasks assigned_to=? OR created_by=? LIMIT ? OFFSET ?",
                  (session["user_id"], session["user_id"], per_page, offset))
    else:
        c.execute("SELECT COUNT(*) FROM tasks")
        total = c.fetchone()[0]

        c.execute("SELECT * FROM tasks LIMIT ? OFFSET ?",
                  (per_page, offset))

    tasks_list = c.fetchall()
    conn.close()

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        "tasks.html",
        tasks=tasks_list,
        page=page,
        total_pages=total_pages
    )

@app.route("/update_task/<int:task_id>", methods=["GET", "POST"])
@role_required(["user", "manager", "admin"])
def update_task(task_id):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("SELECT * FROM tasks WHERE id=?", (task_id,))
    task = c.fetchone()

    if request.method == "POST":
        status = request.form["status"]
        c.execute("UPDATE tasks SET status=? WHERE id=?", (status, task_id))
        c.execute("INSERT INTO logs (user_id, action, target_type, target_id) VALUES (?, ?, ?, ?)",
                  (session["user_id"], "Updated Task", "task", task_id))
        conn.commit()
        conn.close()
        
        flash("Task updated successfully!", "success")
        return redirect("/tasks")
    
    conn.close()
    return redirect("/tasks")

@app.route("/delete_task/<int:task_id>", methods=["POST"])
@role_required(["user", "manager", "admin"])
def delete_task(task_id):
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    if session["role"] == "user":
        c.execute("DELETE FROM tasks WHERE id=? AND created_by=?", (task_id, session["user_id"]))
        c.execute("INSERT INTO logs (user_id, action, target_type, target_id) VALUES (?, ?, ?, ?)",
                  (session["user_id"], "Deleted Task", "task", task_id))
    else:
        c.execute("DELETE FROM tasks WHERE id=?", (task_id,))
        c.execute("INSERT INTO logs (user_id, action, target_type, target_id) VALUES (?, ?, ?, ?)",
                  (session["user_id"], "Deleted Task", "task", task_id))
    
    conn.commit()
    conn.close()

    flash("Task deleted successfully!", "success")
    return redirect("/tasks")

# @app.route("/logs")
# @role_required(["admin"])
# def view_logs():
#     conn = sqlite3.connect("database.db")
#     c = conn.cursor()
#     c.execute("SELECT * FROM logs")
#     logs_list = c.fetchall()

#     conn.close()
#     return render_template("logs.html", logs=logs_list)

@app.route("/logs")
@role_required(["admin"])
def view_logs():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    page = request.args.get("page", 1, type=int)
    per_page = 10
    offset = (page - 1) * per_page

    c.execute("SELECT COUNT(*) FROM logs")
    total = c.fetchone()[0]

    c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ? OFFSET ?",
              (per_page, offset))

    logs_list = c.fetchall()
    conn.close()

    total_pages = (total + per_page - 1) // per_page

    return render_template(
        "logs.html",
        logs=logs_list,
        page=page,
        total_pages=total_pages
    )

@app.route("/")
def home():
    return render_template("index.html")
if __name__ == "__main__":
    app.run(debug=True)