from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3, hashlib, random, string, os
from datetime import datetime
import io, base64
import qrcode
from flask import send_file

app = Flask(__name__)
app.secret_key = "S_U_P_E_R_S_E_C_R_E_T"
DATABASE = "carwash.db"
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif'}

# ---------------- Database ----------------
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        c = conn.cursor()
        # Users
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT,
                        is_admin INTEGER DEFAULT 0,
                        full_name TEXT,
                        phone TEXT)''')
        # Services
        c.execute('''CREATE TABLE IF NOT EXISTS services (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT,
                        price REAL)''')
        # Bookings
        c.execute('''CREATE TABLE IF NOT EXISTS bookings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        service_id INTEGER,
                        date TEXT,
                        time TEXT,
                        queue_code TEXT UNIQUE,
                        paid INTEGER DEFAULT 0,
                        slip_filename TEXT,
                        FOREIGN KEY(user_id) REFERENCES users(id),
                        FOREIGN KEY(service_id) REFERENCES services(id))''')
        # Admin
        c.execute("SELECT * FROM users WHERE username='admin'")
        if not c.fetchone():
            admin_pass = hashlib.sha256("admin123".encode()).hexdigest()
            c.execute("INSERT INTO users(username,password,is_admin,full_name) VALUES (?,?,1,?)",
                      ("admin", admin_pass, "ผู้ดูแลระบบ"))
        # Sample services
        c.execute("SELECT COUNT(*) FROM services")
        if c.fetchone()[0] == 0:
            # Seed prices aligned with homepage examples: 199, 399, 699
            c.executemany("INSERT INTO services(name,price) VALUES (?,?)",
                          [("ล้าง+ดูดฝุ่น",199),("ล้างพรีเมี่ยม",399),("เคลือบสี",699)])
        conn.commit()

# ---------------- Helper ----------------

def hash_password(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def generate_queue_code(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

# ---------------- Routes ----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/services")
def services():
    with get_db() as conn:
        services_list = conn.execute("SELECT * FROM services").fetchall()
    return render_template("services.html", services=services_list)

@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        confirm  = request.form["confirm"].strip()
        full_name = request.form.get("full_name","").strip()
        phone = request.form.get("phone","").strip()
        if not username or not password:
            flash("กรุณากรอกข้อมูลให้ครบ","warning")
            return redirect(url_for("signup"))
        if password != confirm:
            flash("รหัสผ่านไม่ตรงกัน","danger")
            return redirect(url_for("signup"))
        try:
            with get_db() as conn:
                conn.execute("INSERT INTO users(username,password,full_name,phone) VALUES (?,?,?,?)",
                             (username, hash_password(password), full_name, phone))
                conn.commit()
            flash("สมัครสมาชิกสำเร็จ! กรุณาเข้าสู่ระบบ","success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("ชื่อผู้ใช้นี้ถูกใช้แล้ว","danger")
    return render_template("signup.html")               

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u, p = request.form["username"], hash_password(request.form["password"])
        with get_db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=? AND password=?",(u,p)).fetchone()
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = bool(user["is_admin"])
            flash("เข้าสู่ระบบสำเร็จ","success")
            return redirect(url_for("index"))
        flash("ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง","danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("ออกจากระบบแล้ว","info")
    return redirect(url_for("index"))

@app.route("/booking", methods=["GET","POST"])
def booking():
    if "user_id" not in session:
        flash("กรุณาเข้าสู่ระบบก่อนจอง","warning")
        return redirect(url_for("login"))
        
    selected_service = request.args.get('service_id')
    if selected_service:
        try:
            selected_service = int(selected_service)
        except ValueError:
            selected_service = None
            
    with get_db() as conn:
        services_list = conn.execute("SELECT * FROM services").fetchall()
        new_qrcode = None
        
        if request.method == "POST":
            date = request.form["date"]
            time = request.form["time"]
            service_id = request.form["service"]
            
            # Validate datetime not in the past
            try:
                dt_obj = datetime.strptime(f"{date} {time}", "%Y-%m-%d %H:%M")
            except Exception:
                flash("รูปแบบวันที่/เวลาไม่ถูกต้อง","danger")
                return redirect(url_for('booking'))
            
            if dt_obj < datetime.now():
                flash("ไม่สามารถจองคิวย้อนหลังได้ กรุณาเลือกวันที่/เวลาในอนาคต","warning")
                return redirect(url_for('booking'))

            queue_code = generate_queue_code()
            conn.execute("INSERT INTO bookings(user_id,service_id,date,time,queue_code) VALUES (?,?,?,?,?)",
                         (session["user_id"], service_id, date, time, queue_code))
            conn.commit()
            flash(f"จองคิวเรียบร้อย! รหัสคิวของคุณ: {queue_code}","success")

            # สร้าง QR code
            qr_img = qrcode.make(queue_code)
            buf = io.BytesIO()
            qr_img.save(buf, format="PNG")
            buf.seek(0)
            new_qrcode = base64.b64encode(buf.read()).decode("ascii")

        rows = conn.execute("""
            SELECT b.id, b.queue_code, b.paid, s.name, b.date, b.time, b.slip_filename
            FROM bookings b
            JOIN services s ON b.service_id=s.id
            WHERE b.user_id=?
            ORDER BY b.date DESC, b.time DESC
        """,(session["user_id"],)).fetchall()

        # Build display list with is_past flag
        bookings = []
        for r in rows:
            try:
                # Use strftime to handle dates gracefully even if time is missing/invalid
                dt_obj = datetime.strptime(f"{r['date']} {r['time']}", "%Y-%m-%d %H:%M")
            except Exception:
                dt_obj = None
            
            # Check if booking date/time is in the past
            is_past = (dt_obj < datetime.now()) if dt_obj else False
            
            bookings.append({
                'id': r['id'],
                'name': r['name'],
                'date': r['date'],
                'time': r['time'],
                'queue_code': r['queue_code'],
                'paid': bool(r['paid']),
                'slip_filename': r['slip_filename'],
                'is_past': is_past
            })

    return render_template("booking.html", services=services_list, bookings=bookings, new_qrcode=new_qrcode, selected_service=selected_service)


@app.route('/services/<int:service_id>')
def service_detail(service_id):
    # redirect to booking page with the selected service prefilled
    return redirect(url_for('booking', service_id=service_id))


@app.route("/pay/<int:booking_id>")
def pay(booking_id):
    if "user_id" not in session:
        flash("กรุณาเข้าสู่ระบบก่อนชำระเงิน","warning")
        return redirect(url_for("login"))
        
    # This route is mainly kept for backward compatibility; actual payment uses slip upload
    with get_db() as conn:
        conn.execute("UPDATE bookings SET paid=1 WHERE id=? AND user_id=?", (booking_id, session["user_id"]))
        conn.commit()
    flash("สถานะการชำระเงินถูกอัปเดต","success")
    return redirect(url_for("booking"))


@app.route('/upload_slip/<int:booking_id>', methods=['POST'])
def upload_slip(booking_id):
    if 'user_id' not in session:
        flash('กรุณาเข้าสู่ระบบก่อนอัปโหลดสลิป', 'warning')
        return redirect(url_for('login'))
        
    if 'slip' not in request.files:
        flash('ไม่พบไฟล์สลิป', 'danger')
        return redirect(url_for('booking'))
        
    file = request.files['slip']
    
    if file.filename == '':
        flash('กรุณาเลือกไฟล์', 'warning')
        return redirect(url_for('booking'))
        
    if file and allowed_file(file.filename):
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        ext = file.filename.rsplit('.', 1)[1].lower()
        fname = f"slip_{booking_id}_{int(datetime.now().timestamp())}.{ext}"
        fpath = os.path.join(UPLOAD_FOLDER, fname)
        
        # ------------------- ส่วนที่ปรับปรุง -------------------
        try:
            # 1. พยายามบันทึกไฟล์ (จุดที่มักเกิด Permission Denied)
            file.save(fpath) 
            
            # 2. บันทึกชื่อไฟล์ลง DB
            with get_db() as conn:
                conn.execute("UPDATE bookings SET slip_filename=?, paid=1 WHERE id=? AND user_id=?",
                             (fname, booking_id, session['user_id']))
                conn.commit()
                
            flash('อัปโหลดสลิปเรียบร้อย ทีมงานจะตรวจสอบและยืนยันการชำระ', 'success')
            
        except Exception as e:
            # ดักจับข้อผิดพลาดและพิมพ์ลงใน Console
            print(f"\n\n🚨🚨 FILE SAVE/DB ERROR: {e} 🚨🚨") 
            flash(f'เกิดข้อผิดพลาดในการบันทึกสลิป กรุณาลองใหม่ (Error: {e.__class__.__name__})', 'danger')
        # --------------------------------------------------------

    else:
        flash('ชนิดไฟล์ไม่รองรับ (png,jpg,jpeg,gif)', 'danger')
        
    return redirect(url_for('booking'))


@app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
def cancel_booking(booking_id):
    """
    View Function สำหรับยกเลิกการจอง 
    """
    if 'user_id' not in session:
        flash('กรุณาเข้าสู่ระบบก่อนยกเลิกการจอง', 'warning')
        return redirect(url_for('login'))
    
    with get_db() as conn:
        # ดึงข้อมูลการจองเพื่อแสดงรหัสคิวใน flash message
        booking = conn.execute("SELECT queue_code FROM bookings WHERE id=? AND user_id=?", 
                                (booking_id, session['user_id'])).fetchone()
        
        if booking:
            # ลบรายการจองออกจากฐานข้อมูล
            conn.execute("DELETE FROM bookings WHERE id=? AND user_id=?", 
                         (booking_id, session['user_id']))
            conn.commit()
            flash(f'ยกเลิกการจองรหัสคิว {booking["queue_code"]} เรียบร้อยแล้ว', 'info')
        else:
            flash('ไม่พบรายการจองที่คุณต้องการยกเลิก หรือคุณไม่มีสิทธิ์ยกเลิกรายการนี้', 'danger')
            
    return redirect(url_for('booking'))

# ----------------- ADMIN ACTIONS -----------------

@app.route('/admin/confirm_payment/<int:booking_id>', methods=['POST'])
def admin_confirm_payment(booking_id):
    """
    ผู้ดูแลระบบยืนยันการชำระเงิน
    """
    if not session.get("is_admin"):
        flash("สำหรับผู้ดูแลระบบเท่านั้น", "danger")
        return redirect(url_for("login"))
    
    with get_db() as conn:
        conn.execute("UPDATE bookings SET paid=1 WHERE id=?", (booking_id,))
        conn.commit()
        flash(f'ยืนยันการชำระเงินสำหรับการจอง ID {booking_id} เรียบร้อย', 'success')
        
    return redirect(url_for('admin'))

@app.route('/admin/cancel/<int:booking_id>', methods=['POST'])
def admin_cancel_booking(booking_id):
    """
    ผู้ดูแลระบบยกเลิก/ลบการจอง
    """
    if not session.get("is_admin"):
        flash("สำหรับผู้ดูแลระบบเท่านั้น", "danger")
        return redirect(url_for("login"))
        
    with get_db() as conn:
        # Fetch queue code for confirmation message
        booking = conn.execute("SELECT queue_code FROM bookings WHERE id=?", (booking_id,)).fetchone()
        
        if booking:
            conn.execute("DELETE FROM bookings WHERE id=?", (booking_id,))
            conn.commit()
            flash(f'รายการจองคิว {booking["queue_code"]} ถูกยกเลิกโดยผู้ดูแลระบบแล้ว', 'info')
        else:
            flash(f'ไม่พบรายการจอง ID {booking_id}', 'danger')
            
    return redirect(url_for('admin'))

# -------------------------------------------------

@app.route("/admin", methods=["GET","POST"])
def admin():
    if not session.get("is_admin"):
        flash("สำหรับผู้ดูแลระบบเท่านั้น","danger")
        return redirect(url_for("login"))
        
    with get_db() as conn:
        if request.method == "POST":
            for sid in request.form:
                conn.execute("UPDATE services SET price=? WHERE id=?", (request.form[sid], sid))
            conn.commit() # Commit การเปลี่ยนแปลงราคา
            flash("อัปเดตราคาเรียบร้อย", "success")
            
        services_list = conn.execute("SELECT * FROM services").fetchall()
        
        report = conn.execute("""
            SELECT date,
                   COUNT(*) AS total_bookings,
                   SUM(s.price) AS total_price,
                   (
                     SELECT GROUP_CONCAT(t.time, ', ')
                     FROM (
                       SELECT time FROM bookings t WHERE t.date = b.date ORDER BY time
                     ) t
                   ) AS times
            FROM bookings b
            JOIN services s ON b.service_id=s.id
            GROUP BY date
            ORDER BY date DESC
        """).fetchall()
        
        # Compute totals
        total_bookings = sum([r['total_bookings'] or 0 for r in report]) if report else 0
        total_income = sum([r['total_price'] or 0 for r in report]) if report else 0
        
        # Recent bookings for admin (show date + time + user + service)
        bookings = conn.execute("""
            SELECT b.id, b.date, b.time, b.queue_code, b.paid, s.name AS service_name,
                   u.username, u.full_name
            FROM bookings b
            JOIN services s ON b.service_id=s.id
            LEFT JOIN users u ON b.user_id = u.id
            ORDER BY b.date DESC, b.time DESC
            LIMIT 200
        """).fetchall()
        
    return render_template("admin.html", services=services_list, report=report, bookings=bookings,
                           total_bookings=total_bookings, total_income=total_income)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)