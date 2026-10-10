
import os
import sqlite3
from pathlib import Path
from functools import wraps
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, abort
)

app = Flask(__name__)
app.secret_key = os.environ.get("PETORBIT_SECRET", "change-this-secret-key")
ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "petorbit.db"
UPLOADS = ROOT / "static" / "uploads"
UPLOADS.mkdir(parents=True, exist_ok=True)
ALLOWED = {"png", "jpg", "jpeg", "webp"}


def connect():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    return con


def init_db():
    with connect() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );

        CREATE TABLE IF NOT EXISTS pets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            name TEXT NOT NULL,
            species TEXT NOT NULL,
            breed TEXT DEFAULT '',
            birth_date TEXT DEFAULT '',
            weight REAL DEFAULT 0,
            photo TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS food (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            species TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL DEFAULT 0,
            description TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            food_id INTEGER NOT NULL REFERENCES food(id),
            quantity INTEGER NOT NULL,
            total REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'Placed',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS feeding (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pet_id INTEGER NOT NULL REFERENCES pets(id) ON DELETE CASCADE,
            food_name TEXT NOT NULL,
            amount TEXT DEFAULT '',
            log_date TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS growth (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pet_id INTEGER NOT NULL REFERENCES pets(id) ON DELETE CASCADE,
            log_date TEXT NOT NULL,
            weight REAL NOT NULL,
            height REAL DEFAULT 0,
            notes TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS health (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pet_id INTEGER NOT NULL REFERENCES pets(id) ON DELETE CASCADE,
            kind TEXT NOT NULL,
            record_date TEXT NOT NULL,
            next_due TEXT DEFAULT '',
            notes TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            pet_name TEXT NOT NULL,
            species TEXT NOT NULL,
            report_type TEXT NOT NULL,
            location TEXT NOT NULL,
            contact TEXT NOT NULL,
            description TEXT DEFAULT '',
            photo TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Open',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS adoption (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            pet_name TEXT NOT NULL,
            species TEXT NOT NULL,
            age TEXT DEFAULT '',
            location TEXT NOT NULL,
            contact TEXT NOT NULL,
            description TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Available'
        );
        """)

        # Migrate older databases without deleting existing pet data.
        # CREATE TABLE IF NOT EXISTS does not add columns to an existing table.
        pet_columns = {
            row["name"]
            for row in con.execute("PRAGMA table_info(pets)").fetchall()
        }

        # SQLite requires added columns on populated tables to have a safe default
        # when existing rows are present.
        pet_migrations = {
            "user_id": "INTEGER REFERENCES users(id)",
            "name": "TEXT NOT NULL DEFAULT ''",
            "species": "TEXT NOT NULL DEFAULT ''",
            "breed": "TEXT DEFAULT ''",
            "birth_date": "TEXT DEFAULT ''",
            "weight": "REAL DEFAULT 0",
            "photo": "TEXT DEFAULT ''",
        }

        for column_name, column_definition in pet_migrations.items():
            if column_name not in pet_columns:
                con.execute(
                    f"ALTER TABLE pets ADD COLUMN {column_name} {column_definition}"
                )


def current_user():
    if "user_id" not in session:
        return None
    with connect() as con:
        return con.execute(
            "SELECT id,name,email,role FROM users WHERE id=?",
            (session["user_id"],)
        ).fetchone()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for("login"))
        if user["role"] != "admin":
            abort(403)
        return fn(*args, **kwargs)
    return wrapper


def save_photo(upload):
    if not upload or not upload.filename:
        return ""
    if "." not in upload.filename:
        return ""
    if upload.filename.rsplit(".", 1)[1].lower() not in ALLOWED:
        flash("Photo must be PNG, JPG, JPEG or WEBP.", "error")
        return ""
    name = secure_filename(upload.filename)
    target = UPLOADS / name
    stem, suffix = target.stem, target.suffix
    n = 1
    while target.exists():
        target = UPLOADS / f"{stem}_{n}{suffix}"
        n += 1
    upload.save(target)
    return target.name


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or "@" not in email or len(password) < 8:
            flash("Enter a name, valid email and password of at least 8 characters.", "error")
        else:
            try:
                with connect() as con:
                    con.execute(
                        "INSERT INTO users(name,email,password) VALUES(?,?,?)",
                        (name, email, generate_password_hash(password))
                    )
                flash("Account created. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That email is already registered.", "error")
    return render_template("auth.html", mode="register")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with connect() as con:
            user = con.execute(
                "SELECT * FROM users WHERE email=?", (email,)
            ).fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard"))
        flash("Incorrect email or password.", "error")
    return render_template("auth.html", mode="login")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    user = current_user()
    with connect() as con:
        if user["role"] == "admin":
            pets = con.execute("SELECT p.*,u.name AS owner FROM pets p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC").fetchall()
            foods = con.execute("SELECT * FROM food ORDER BY id DESC").fetchall()
            reports = con.execute("SELECT r.*,u.name AS reporter FROM reports r JOIN users u ON u.id=r.user_id ORDER BY r.id DESC").fetchall()
            adoptions = con.execute("SELECT a.*,u.name AS poster FROM adoption a JOIN users u ON u.id=a.user_id ORDER BY a.id DESC").fetchall()
        else:
            pets = con.execute("SELECT * FROM pets WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
            foods = con.execute("SELECT * FROM food ORDER BY name").fetchall()
            reports = con.execute("SELECT r.*,u.name AS reporter FROM reports r JOIN users u ON u.id=r.user_id ORDER BY r.id DESC").fetchall()
            adoptions = con.execute("SELECT a.*,u.name AS poster FROM adoption a JOIN users u ON u.id=a.user_id ORDER BY a.id DESC").fetchall()

        pet_ids = [p["id"] for p in pets]
        growth = []
        health = []
        feeding = []
        orders = con.execute(
            "SELECT o.*,f.name AS food_name FROM orders o JOIN food f ON f.id=o.food_id WHERE o.user_id=? ORDER BY o.id DESC",
            (user["id"],)
        ).fetchall()

        if pet_ids:
            marks = ",".join("?" for _ in pet_ids)
            growth = con.execute(
                f"SELECT g.*,p.name AS pet_name FROM growth g JOIN pets p ON p.id=g.pet_id WHERE g.pet_id IN ({marks}) ORDER BY g.log_date DESC",
                pet_ids
            ).fetchall()
            health = con.execute(
                f"SELECT h.*,p.name AS pet_name FROM health h JOIN pets p ON p.id=h.pet_id WHERE h.pet_id IN ({marks}) ORDER BY h.record_date DESC",
                pet_ids
            ).fetchall()
            feeding = con.execute(
                f"SELECT f.*,p.name AS pet_name FROM feeding f JOIN pets p ON p.id=f.pet_id WHERE f.pet_id IN ({marks}) ORDER BY f.id DESC LIMIT 20",
                pet_ids
            ).fetchall()

    return render_template(
        "dashboard.html", user=user, pets=pets, foods=foods,
        reports=reports, adoptions=adoptions, growth=growth,
        health=health, feeding=feeding, orders=orders, today=date.today().isoformat()
    )



@app.post("/pets/add")
@login_required
def add_pet():
    name = request.form.get("name", "").strip()
    species = request.form.get("species", "").strip()
    pet_type = request.form.get("pet_type", "").strip() or species

    if not name or not (species or pet_type):
        flash("Pet name and species are required.", "error")
        return redirect(url_for("dashboard"))

    photo = save_photo(request.files.get("photo"))

    with connect() as con:
        # Check which columns exist in the current database
        columns = {
            row["name"]
            for row in con.execute("PRAGMA table_info(pets)").fetchall()
        }
        values = {
    "user_id": session.get("user_id"),
    "name": name,
    "species": species or pet_type,
    "pet_type": pet_type or species,
    "breed": request.form.get("breed", "").strip(),
    "birth_date": request.form.get("birth_date", ""),
    "age": request.form.get("age") or 0,
    "weight": float(request.form.get("weight") or 0),
    "owner": request.form.get("owner", "").strip()
             or session.get("username", ""),
    "photo": photo or "",
}
        

        # Insert only columns that exist in this database
        insert_columns = [
            col for col in values if col in columns
        ]

        # Include any other required columns that lack defaults
        missing_required = [
            row["name"]
            for row in con.execute("PRAGMA table_info(pets)").fetchall()
            if row["notnull"]
            and row["name"] not in insert_columns
            and row["dflt_value"] is None
            and row["name"] != "id"
        ]

        if missing_required:
            flash(
                "Database needs additional fields: "
                + ", ".join(missing_required),
                "error",
            )
            return redirect(url_for("dashboard"))

        placeholders = ", ".join("?" for _ in insert_columns)
        column_names = ", ".join(insert_columns)

        con.execute(
            f"INSERT INTO pets ({column_names}) "
            f"VALUES ({placeholders})",
            tuple(values[col] for col in insert_columns),
        )

    flash("Pet profile created successfully.", "success")
    return redirect(url_for("dashboard"))


@app.post("/pets/delete/<int:pet_id>")
@login_required
def delete_pet(pet_id):
    with connect() as con:
        pet = con.execute("SELECT * FROM pets WHERE id=?", (pet_id,)).fetchone()
        user = current_user()
        if not pet:
            abort(404)
        if pet["user_id"] != user["id"] and user["role"] != "admin":
            abort(403)
        con.execute("DELETE FROM pets WHERE id=?", (pet_id,))
    flash("Pet profile deleted.", "success")
    return redirect(url_for("dashboard"))


@app.post("/food/add")
@admin_required
def add_food():
    name = request.form.get("name", "").strip()
    species = request.form.get("species", "").strip()
    price = request.form.get("price", type=float)
    stock = request.form.get("stock", type=int)
    if not name or not species or price is None or price < 0 or stock is None or stock < 0:
        flash("Enter valid food details, price and stock.", "error")
    else:
        with connect() as con:
            con.execute(
                "INSERT INTO food(name,species,price,stock,description) VALUES(?,?,?,?,?)",
                (name, species, price, stock, request.form.get("description", "").strip())
            )
        flash("Food product added.", "success")
    return redirect(url_for("dashboard"))


@app.post("/food/order/<int:food_id>")
@login_required
def order_food(food_id):
    quantity = request.form.get("quantity", type=int)
    if not quantity or quantity < 1:
        flash("Quantity must be at least 1.", "error")
        return redirect(url_for("dashboard"))
    with connect() as con:
        food = con.execute("SELECT * FROM food WHERE id=?", (food_id,)).fetchone()
        if not food:
            abort(404)
        if food["stock"] < quantity:
            flash("Not enough stock available.", "error")
        else:
            total = round(food["price"] * quantity, 2)
            con.execute("UPDATE food SET stock=stock-? WHERE id=?", (quantity, food_id))
            con.execute(
                "INSERT INTO orders(user_id,food_id,quantity,total) VALUES(?,?,?,?)",
                (session["user_id"], food_id, quantity, total)
            )
            flash("Demo order placed. No payment was collected.", "success")
    return redirect(url_for("dashboard"))


@app.post("/feeding/add")
@login_required
def add_feeding():
    pet_id = request.form.get("pet_id", type=int)
    with connect() as con:
        pet = con.execute("SELECT id FROM pets WHERE id=? AND user_id=?",
                          (pet_id, session["user_id"])).fetchone()
        if not pet:
            abort(403)
        con.execute(
            "INSERT INTO feeding(pet_id,food_name,amount,log_date) VALUES(?,?,?,?)",
            (pet_id, request.form.get("food_name", "").strip(),
             request.form.get("amount", "").strip(),
             request.form.get("log_date") or date.today().isoformat())
        )
    flash("Feeding log saved.", "success")
    return redirect(url_for("dashboard"))


@app.post("/growth/add")
@login_required
def add_growth():
    pet_id = request.form.get("pet_id", type=int)
    weight = request.form.get("weight", type=float)
    if weight is None or weight < 0:
        flash("Enter a valid weight.", "error")
        return redirect(url_for("dashboard"))
    with connect() as con:
        pet = con.execute("SELECT id FROM pets WHERE id=? AND user_id=?",
                          (pet_id, session["user_id"])).fetchone()
        if not pet:
            abort(403)
        con.execute(
            "INSERT INTO growth(pet_id,log_date,weight,height,notes) VALUES(?,?,?,?,?)",
            (pet_id, request.form.get("log_date") or date.today().isoformat(),
             weight, float(request.form.get("height") or 0),
             request.form.get("notes", "").strip())
        )
        con.execute("UPDATE pets SET weight=? WHERE id=?", (weight, pet_id))
    flash("Growth measurement saved.", "success")
    return redirect(url_for("dashboard"))


@app.post("/health/add")
@login_required
def add_health():
    pet_id = request.form.get("pet_id", type=int)
    kind = request.form.get("kind", "").strip()
    with connect() as con:
        pet = con.execute("SELECT id FROM pets WHERE id=? AND user_id=?",
                          (pet_id, session["user_id"])).fetchone()
        if not pet:
            abort(403)
        if not kind:
            flash("Choose a health record type.", "error")
        else:
            con.execute(
                "INSERT INTO health(pet_id,kind,record_date,next_due,notes) VALUES(?,?,?,?,?)",
                (pet_id, kind, request.form.get("record_date") or date.today().isoformat(),
                 request.form.get("next_due", ""), request.form.get("notes", "").strip())
            )
            flash("Health record saved.", "success")
    return redirect(url_for("dashboard"))


@app.post("/reports/add")
@login_required
def add_report():
    required = ["pet_name", "species", "report_type", "location", "contact"]
    values = {k: request.form.get(k, "").strip() for k in required}
    if not all(values.values()):
        flash("Complete all required report fields.", "error")
    else:
        photo = save_photo(request.files.get("photo"))
        with connect() as con:
            con.execute(
                """INSERT INTO reports(user_id,pet_name,species,report_type,location,
                   contact,description,photo) VALUES(?,?,?,?,?,?,?,?)""",
                (session["user_id"], values["pet_name"], values["species"],
                 values["report_type"], values["location"], values["contact"],
                 request.form.get("description", "").strip(), photo)
            )
        flash("Pet report published.", "success")
    return redirect(url_for("dashboard"))


@app.post("/reports/resolve/<int:report_id>")
@login_required
def resolve_report(report_id):
    with connect() as con:
        report = con.execute("SELECT * FROM reports WHERE id=?", (report_id,)).fetchone()
        if not report:
            abort(404)
        user = current_user()
        if report["user_id"] != user["id"] and user["role"] != "admin":
            abort(403)
        con.execute("UPDATE reports SET status='Resolved' WHERE id=?", (report_id,))
    flash("Report marked resolved.", "success")
    return redirect(url_for("dashboard"))


@app.post("/adoption/add")
@login_required
def add_adoption():
    keys = ["pet_name", "species", "location", "contact"]
    values = [request.form.get(k, "").strip() for k in keys]
    if not all(values):
        flash("Complete the required adoption fields.", "error")
    else:
        with connect() as con:
            con.execute(
                """INSERT INTO adoption(user_id,pet_name,species,age,location,contact,description)
                   VALUES(?,?,?,?,?,?,?)""",
                (session["user_id"], values[0], values[1],
                 request.form.get("age", "").strip(), values[2], values[3],
                 request.form.get("description", "").strip())
            )
        flash("Adoption listing published.", "success")
    return redirect(url_for("dashboard"))


@app.post("/adoption/close/<int:post_id>")
@login_required
def close_adoption(post_id):
    with connect() as con:
        post = con.execute("SELECT * FROM adoption WHERE id=?", (post_id,)).fetchone()
        if not post:
            abort(404)
        user = current_user()
        if post["user_id"] != user["id"] and user["role"] != "admin":
            abort(403)
        con.execute("UPDATE adoption SET status='Closed' WHERE id=?", (post_id,))
    flash("Adoption listing closed.", "success")
    return redirect(url_for("dashboard"))


@app.post("/admin/promote")
@admin_required
def promote_user():
    email = request.form.get("email", "").strip().lower()
    with connect() as con:
        con.execute("UPDATE users SET role='admin' WHERE email=?", (email,))
    flash("If that email exists, its role is now admin.", "success")
    return redirect(url_for("dashboard"))


@app.post("/admin/order-status/<int:order_id>")
@admin_required
def order_status(order_id):
    status = request.form.get("status", "")
    if status not in {"Placed", "Processing", "Completed", "Cancelled"}:
        abort(400)
    with connect() as con:
        con.execute("UPDATE orders SET status=? WHERE id=?", (status, order_id))
    flash("Order status updated.", "success")
    return redirect(url_for("dashboard"))


@app.post("/assistant")
@login_required
def assistant():
    question = request.form.get("question", "").lower()
    if any(word in question for word in ["emergency", "can't breathe", "bleeding", "poison", "seizure"]):
        answer = "This may be urgent. Contact a veterinarian or emergency animal clinic now. Do not give human medicines unless a veterinarian instructs you."
    elif any(word in question for word in ["food", "feeding", "diet"]):
        answer = "Choose species-appropriate, age-appropriate food. Keep fresh water available and ask a veterinarian about portion sizes, allergies, and special diets."
    elif any(word in question for word in ["growth", "weight", "height"]):
        answer = "Record weight and height regularly under similar conditions. Sudden weight change or poor growth should be discussed with a veterinarian."
    elif any(word in question for word in ["vaccine", "vaccination", "health"]):
        answer = "Vaccination schedules depend on species, age, health, and local risks. Ask your veterinarian to create a schedule and record due dates in PETORBIT."
    elif any(word in question for word in ["missing", "lost", "found"]):
        answer = "Post a clear photo, last-seen location, date, and safe contact method. Contact nearby shelters and veterinary clinics. Verify ownership before handing over a pet."
    elif any(word in question for word in ["adopt", "adoption"]):
        answer = "Before adopting, check the pet's health records, temperament, living needs, and expected costs. Meet safely and use a responsible adoption process."
    else:
        answer = "I can share general guidance about feeding, growth, health records, missing pets, and adoption. For diagnosis, medication, or urgent symptoms, contact a qualified veterinarian."
    return render_template("assistant.html", question=question, answer=answer)


@app.errorhandler(403)
def forbidden(_error):
    return "Access denied: you do not have permission to perform this action.", 403



def create_initial_admin():
    email = os.environ.get("PETORBIT_ADMIN_EMAIL", "").strip().lower()
    password = os.environ.get("PETORBIT_ADMIN_PASSWORD", "")
    name = os.environ.get("PETORBIT_ADMIN_NAME", "PETORBIT Admin")

    # Do not create a default administrator with a known password.
    if not email or len(password) < 12:
        print("Admin not seeded. Set PETORBIT_ADMIN_EMAIL and "
              "PETORBIT_ADMIN_PASSWORD (12+ characters).")
        return

    with connect() as con:
        existing = con.execute(
            "SELECT id FROM users WHERE email=?", (email,)
        ).fetchone()

        if existing:
            con.execute(
                "UPDATE users SET role='admin' WHERE email=?", (email,)
            )
        else:
            con.execute(
                """INSERT INTO users(name,email,password,role)
                   VALUES(?,?,?,'admin')""",
                (name, email, generate_password_hash(password))
            )

        
if __name__ == "__main__":
    init_db()
    create_initial_admin()
    app.run(debug=True)
