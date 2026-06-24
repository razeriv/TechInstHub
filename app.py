import os
import uuid
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'секретный-ключ-по-умолчанию')
app.config['JSON_AS_ASCII'] = False
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY', 'super-secret-jwt-key')
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(days=7)

jwt = JWTManager(app)

DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': os.getenv('DB_PORT', 5432),
    'database': os.getenv('DB_NAME', 'TechInstHub'),
    'user': os.getenv('DB_USER', 'iam_user'),
    'password': os.getenv('DB_PASSWORD', ''),
    'client_encoding': 'UTF8'
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
AVATAR_FOLDER = os.path.join(BASE_DIR, 'static', 'avatars')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['AVATAR_FOLDER'] = AVATAR_FOLDER

# Создаём папки с абсолютными путями
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(AVATAR_FOLDER, exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ----- Глобальная защита -----
@app.before_request
def require_login():
    if request.path.startswith('/api/v1/') or request.path.startswith('/static/'):
        return
    public_routes = ['login', 'register', 'static']
    if request.endpoint in public_routes:
        return
    if 'user_id' not in session:
        flash('Войдите в систему!', 'error')
        return redirect(url_for('login'))


# ----- Вспомогательные функции -----
def get_db_connection():
    return psycopg2.connect(**DB_CONFIG, cursor_factory=RealDictCursor)


def get_current_user():
    """Возвращает пользователя и для сессии, и для JWT"""
    if 'user_id' in session:
        return {'id': session['user_id'], 'role': session.get('role')}
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            return {'id': user_id}
    except Exception:
        pass
    return None


def log_action(user_id, action, details=None, ip_address=None):
    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        if user_id:
            cur.execute("SELECT 1 FROM users WHERE id = %s", (user_id,))
            if not cur.fetchone():
                user_id = None
        cur.execute("""
            INSERT INTO logs (user_id, action, details, ip_address, created_at)
            VALUES (%s, %s, %s, %s, NOW())
        """, (user_id, action, details, ip_address))
        conn.commit()
    except Exception as e:
        print(f"⚠️ Ошибка при сохранении лога: {e}")
        if conn:
            conn.rollback()
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Доступ запрещён.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated


def teacher_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') not in ('teacher', 'admin'):
            flash('Только для преподавателей.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated


def ensure_project_chat(project_id, tutor_id, student_id=None):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT title FROM projects WHERE id=%s", (project_id,))
    proj = cur.fetchone()
    chat_name = proj['title'] if proj else "Проект"
    cur.execute("SELECT id FROM chats WHERE name=%s AND is_group=TRUE", (chat_name,))
    chat = cur.fetchone()
    if chat:
        chat_id = chat['id']
    else:
        chat_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO chats (id, name, is_group, created_at, updated_at)
            VALUES (%s, %s, TRUE, NOW(), NOW())
        """, (chat_id, chat_name))
    cur.execute("SELECT 1 FROM chat_members WHERE chat_id=%s AND user_id=%s", (chat_id, tutor_id))
    if not cur.fetchone():
        cur.execute("INSERT INTO chat_members (chat_id, user_id, created_at) VALUES (%s, %s, NOW())",
                    (chat_id, tutor_id))
    if student_id:
        cur.execute("SELECT 1 FROM chat_members WHERE chat_id=%s AND user_id=%s", (chat_id, student_id))
        if not cur.fetchone():
            cur.execute("INSERT INTO chat_members (chat_id, user_id, created_at) VALUES (%s, %s, NOW())",
                        (chat_id, student_id))
    conn.commit()
    cur.close()
    conn.close()
    return chat_id


def create_admin_if_not_exists():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        admin_email = os.getenv('ADMIN_EMAIL', 'admin@techinsthub.com')
        admin_password = os.getenv('ADMIN_PASSWORD', 'Admin123!')
        admin_name = os.getenv('ADMIN_NAME', 'Admin')
        admin_surname = os.getenv('ADMIN_SURNAME', 'Admin')
        cur.execute("SELECT 1 FROM users WHERE email = %s", (admin_email,))
        if not cur.fetchone():
            admin_id = str(uuid.uuid4())
            hashed = generate_password_hash(admin_password)
            cur.execute("""
                INSERT INTO users (id, email, password_hash, first_name, last_name, role, is_active, is_verified, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, 'admin', TRUE, TRUE, NOW(), NOW())
            """, (admin_id, admin_email, hashed, admin_name, admin_surname))
            cur.execute("""
                INSERT INTO admins (user_id, admin_level, created_at, updated_at)
                VALUES (%s, 1, NOW(), NOW())
            """, (admin_id,))
            conn.commit()
            print(f"✅ Администратор создан: {admin_email} / {admin_password}")
        else:
            print("👤 Администратор уже существует.")
    except Exception as e:
        print("❌ Ошибка при создании админа:", e)
    finally:
        cur.close()
        conn.close()

# ----- Маршруты -----
@app.route('/')
def index():
    conn = get_db_connection()
    cur = conn.cursor()

    # Получаем проекты для рекомендаций
    cur.execute("""
        SELECT p.id, p.title, p.description, p.deadline, p.difficulty, p.max_students,
               u.first_name AS name, u.last_name AS surname, u.avatar_url,
               (SELECT image_url FROM images WHERE entity_type='project' AND entity_id=p.id ORDER BY sort_order LIMIT 1) AS image_url,
               (SELECT COUNT(*) FROM applications WHERE project_id=p.id AND status='accepted') AS accepted_count
        FROM projects p
        JOIN users u ON p.id_tutor = u.id
        WHERE p.status = 'открыт'
        ORDER BY p.created_at DESC
        LIMIT 3
    """)
    projects = cur.fetchall()

    # Получаем ВСЕ публикации (новости, стажировки, мероприятия) для раздела новостей
    cur.execute("""
        SELECT id, title, content, image_url, published_at, 
               COALESCE(type, 'news') as type
        FROM news_feed
        ORDER BY published_at DESC
        LIMIT 3
    """)
    all_news = cur.fetchall()

    cur.close()
    conn.close()
    return render_template('index.html', projects=projects, all_news=all_news)


# ----- Маршруты для стажировок и мероприятий -----
@app.route('/internships')
def internships_list():
    """Страница со стажировками"""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, title, content, image_url, published_at, type
            FROM news_feed
            WHERE type = 'internship'
            ORDER BY published_at DESC
        """)
        internships = cur.fetchall()
    except Exception as e:
        print(f"Ошибка при получении стажировок: {e}")
        internships = []
    finally:
        cur.close()
        conn.close()
    return render_template('internships.html', internships=internships)


@app.route('/events')
def events_list():
    """Страница с мероприятиями"""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, title, content, image_url, published_at, type,
                   event_date, event_location
            FROM news_feed
            WHERE type = 'event'
            ORDER BY event_date ASC NULLS LAST
        """)
        events = cur.fetchall()
    except Exception as e:
        print(f"Ошибка при получении мероприятий: {e}")
        events = []
    finally:
        cur.close()
        conn.close()
    return render_template('events.html', events=events)


@app.route('/news')
@app.route('/news/<string:type_filter>')
def news_by_type(type_filter='all'):
    """Фильтрация новостей по типу"""
    if type_filter not in ['news', 'internship', 'event', 'all']:
        type_filter = 'all'

    conn = get_db_connection()
    cur = conn.cursor()

    try:
        if type_filter == 'all':
            cur.execute("""
                SELECT id, title, content, image_url, published_at, type,
                       event_date, event_location
                FROM news_feed
                ORDER BY published_at DESC
            """)
        else:
            cur.execute("""
                SELECT id, title, content, image_url, published_at, type,
                       event_date, event_location
                FROM news_feed
                WHERE type = %s
                ORDER BY published_at DESC
            """, (type_filter,))

        all_news = cur.fetchall()
    except Exception as e:
        print(f"Ошибка при получении новостей: {e}")
        all_news = []
    finally:
        cur.close()
        conn.close()

    return render_template('news.html', news=all_news, active_filter=type_filter)


@app.route('/catalog')
def catalog():
    search = request.args.get('search', '')
    topic_id = request.args.get('topic', '')
    complexity = request.args.get('complexity', '')
    conn = get_db_connection()
    cur = conn.cursor()
    query = """
        SELECT p.id, p.title, p.description, p.deadline, p.difficulty, p.max_students,
               u.first_name AS name, u.last_name AS surname, u.avatar_url, p.topic_id,
               (SELECT image_url FROM images WHERE entity_type='project' AND entity_id=p.id ORDER BY sort_order LIMIT 1) AS image_url,
               (SELECT COUNT(*) FROM applications WHERE project_id=p.id AND status='accepted') AS accepted_count
        FROM projects p
        JOIN users u ON p.id_tutor = u.id
        WHERE p.status = 'открыт'
    """
    params = []
    if search:
        query += " AND p.title ILIKE %s"
        params.append(f'%{search}%')
    if topic_id:
        query += " AND p.topic_id = %s"
        params.append(topic_id)
    if complexity:
        query += " AND p.difficulty = %s"
        params.append(complexity)
    query += " ORDER BY p.created_at DESC"
    cur.execute(query, params)
    projects = cur.fetchall()
    cur.execute("SELECT id, name FROM topics ORDER BY name")
    topics = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('catalog_projects.html', projects=projects, topics=topics,
                           search_query=search, selected_topic=topic_id, selected_complexity=complexity)


@app.route('/project/<uuid:project_id>')
def project_detail(project_id):
    project_id_str = str(project_id)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT p.*, u.first_name AS tutor_name, u.last_name AS tutor_surname, u.avatar_url AS tutor_avatar,
               t.name AS topic_name,
               (SELECT image_url FROM images WHERE entity_type='project' AND entity_id=p.id ORDER BY sort_order LIMIT 1) AS image_url
        FROM projects p
        JOIN users u ON p.id_tutor = u.id
        LEFT JOIN topics t ON p.topic_id = t.id
        WHERE p.id = %s
    """, (project_id_str,))
    project = cur.fetchone()
    if not project:
        flash('Проект не найден.', 'error')
        return redirect(url_for('catalog'))

    cur.execute("""
        SELECT image_url FROM images 
        WHERE entity_type='project' AND entity_id=%s 
        ORDER BY sort_order
    """, (project_id_str,))
    project_images = [img['image_url'] for img in cur.fetchall()]

    has_accepted = False
    if session.get('role') == 'student' and session.get('user_id'):
        cur.execute("""
            SELECT 1 FROM applications
            WHERE project_id = %s AND student_id = %s AND status = 'accepted'
        """, (project_id_str, session['user_id']))
        has_accepted = cur.fetchone() is not None
    cur.close()
    conn.close()
    return render_template('project_card.html', project=project, has_accepted_application=has_accepted,
                           project_images=project_images)


@app.route('/apply/<uuid:project_id>', methods=['POST'])
def apply_project(project_id):
    if session.get('role') != 'student':
        flash('Только студенты могут подавать заявки.', 'error')
        return redirect(url_for('project_detail', project_id=project_id))
    project_id_str = str(project_id)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM applications WHERE project_id = %s AND student_id = %s",
                (project_id_str, session['user_id']))
    if cur.fetchone():
        flash('Вы уже подали заявку на этот проект.', 'warning')
    else:
        cur.execute("""
            INSERT INTO applications (id, project_id, student_id, status, applied_at, updated_at)
            VALUES (%s, %s, %s, 'pending', NOW(), NOW())
        """, (str(uuid.uuid4()), project_id_str, session['user_id']))
        conn.commit()
        log_action(session['user_id'], 'apply', f'Заявка на проект {project_id}')
        flash('Заявка отправлена преподавателю.', 'success')
    cur.close()
    conn.close()
    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/complete/<uuid:project_id>', methods=['POST'])
def complete_project(project_id):
    if session.get('role') != 'student':
        flash('Недостаточно прав.', 'error')
        return redirect(url_for('project_detail', project_id=project_id))
    project_id_str = str(project_id)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT 1 FROM applications
        WHERE project_id = %s AND student_id = %s AND status = 'accepted'
    """, (project_id_str, session['user_id']))
    if cur.fetchone():
        cur.execute("UPDATE projects SET status = 'завершён', updated_at = NOW() WHERE id = %s", (project_id_str,))
        conn.commit()
        log_action(session['user_id'], 'complete_project', f'Проект {project_id} завершён')
        flash('Проект успешно завершён!', 'success')
    else:
        flash('Вы не можете завершить этот проект.', 'error')
    cur.close()
    conn.close()
    return redirect(url_for('project_detail', project_id=project_id))


@app.route('/my_projects')
@teacher_required
def my_projects():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT id, title, status, created_at, max_students
        FROM projects
        WHERE id_tutor = %s
        ORDER BY created_at DESC
    """, (session['user_id'],))
    projects = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('my_projects.html', projects=projects)


@app.route('/add_project', methods=['GET', 'POST'])
@teacher_required
def add_project():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM topics ORDER BY name")
    topics = cur.fetchall()
    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        requirements = request.form.get('requirements', '')
        details = request.form.get('details', '')
        topic_id = request.form.get('topic_id') or None
        difficulty = request.form.get('difficulty', 'легкий')
        deadline = request.form.get('deadline') or None
        max_students = request.form.get('max_students', 1)
        try:
            max_students = int(max_students)
        except:
            max_students = 1

        project_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO projects (id, id_tutor, title, description, requirements, details,
                                  topic_id, difficulty, deadline, status, created_at, updated_at, max_students)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'открыт', NOW(), NOW(), %s)
        """, (project_id, session['user_id'], title, description, requirements,
              details, topic_id, difficulty, deadline, max_students))

        images = request.files.getlist('images')
        for idx, img in enumerate(images):
            if img and allowed_file(img.filename):
                filename = secure_filename(img.filename)
                unique_name = f"{uuid.uuid4().hex}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                img.save(filepath)
                image_url = f"uploads/{unique_name}"
                cur.execute("""
                    INSERT INTO images (id, entity_type, entity_id, image_url, image_type, sort_order, is_active, created_at, updated_at)
                    VALUES (%s, 'project', %s, %s, 'main', %s, TRUE, NOW(), NOW())
                """, (str(uuid.uuid4()), project_id, image_url, idx))

        conn.commit()
        log_action(session['user_id'], 'add_project', f'Создан проект {title}')
        flash('Проект создан!', 'success')
        return redirect(url_for('my_projects'))
    cur.close()
    conn.close()
    return render_template('add_project.html', topics=topics)


@app.route('/edit_project/<uuid:project_id>', methods=['GET', 'POST'])
@teacher_required
def edit_project(project_id):
    project_id_str = str(project_id)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM projects WHERE id = %s AND id_tutor = %s", (project_id_str, session['user_id']))
    project = cur.fetchone()
    if not project:
        flash('Проект не найден или доступ запрещён.', 'error')
        return redirect(url_for('my_projects'))

    cur.execute("SELECT id, name FROM topics")
    topics = cur.fetchall()

    cur.execute("SELECT image_url FROM images WHERE entity_type='project' AND entity_id=%s ORDER BY sort_order",
                (project_id_str,))
    existing_images = cur.fetchall()

    if request.method == 'POST':
        title = request.form['title']
        description = request.form.get('description', '')
        requirements = request.form.get('requirements', '')
        details = request.form.get('details', '')
        topic_id = request.form.get('topic_id') or None
        difficulty = request.form.get('difficulty')
        deadline = request.form.get('deadline') or None
        status = request.form.get('status', 'открыт')
        max_students = request.form.get('max_students', 1)
        try:
            max_students = int(max_students)
        except:
            max_students = 1

        cur.execute("""
            UPDATE projects SET title=%s, description=%s, requirements=%s, details=%s,
                topic_id=%s, difficulty=%s, deadline=%s, status=%s, max_students=%s, updated_at=NOW()
            WHERE id=%s
        """, (title, description, requirements, details, topic_id, difficulty, deadline, status, max_students,
              project_id_str))

        images = request.files.getlist('images')
        for idx, img in enumerate(images):
            if img and allowed_file(img.filename):
                filename = secure_filename(img.filename)
                unique_name = f"{uuid.uuid4().hex}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                img.save(filepath)
                image_url = f"uploads/{unique_name}"
                cur.execute("""
                    INSERT INTO images (id, entity_type, entity_id, image_url, image_type, sort_order, is_active, created_at, updated_at)
                    VALUES (%s, 'project', %s, %s, 'main', %s, TRUE, NOW(), NOW())
                """, (str(uuid.uuid4()), project_id_str, image_url, idx))

        conn.commit()
        log_action(session['user_id'], 'edit_project', f'Изменён проект {project_id}')
        flash('Изменения сохранены.', 'success')
        return redirect(url_for('my_projects'))
    cur.close()
    conn.close()
    return render_template('edit_project.html', project=project, topics=topics, existing_images=existing_images)


@app.route('/delete_project_image', methods=['POST'])
@teacher_required
def delete_project_image():
    data = request.get_json()
    image_url = data.get('image_url')
    project_id = data.get('project_id')
    if image_url and project_id:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM images WHERE image_url=%s AND entity_id=%s", (image_url, project_id))
        conn.commit()
        cur.close()
        conn.close()
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], image_url.replace('uploads/', ''))
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'success': True})
    return jsonify({'success': False})


@app.route('/project_applications/<uuid:project_id>')
@teacher_required
def project_applications(project_id):
    project_id_str = str(project_id)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM projects WHERE id=%s AND id_tutor=%s", (project_id_str, session['user_id']))
    if not cur.fetchone():
        flash('Нет доступа к заявкам этого проекта.', 'error')
        return redirect(url_for('my_projects'))
    cur.execute("""
        SELECT a.id, a.status, a.applied_at, u.id AS student_id, u.first_name, u.last_name, u.email, u.avatar_url
        FROM applications a
        JOIN users u ON a.student_id = u.id
        WHERE a.project_id = %s
        ORDER BY a.applied_at
    """, (project_id_str,))
    apps = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('project_applications.html', apps=apps)


@app.route('/update_application/<uuid:app_id>/<status>', methods=['POST'])
@teacher_required
def update_application(app_id, status):
    if status not in ('accepted', 'rejected'):
        flash('Неверный статус.', 'error')
        return redirect(request.referrer or url_for('my_projects'))
    app_id_str = str(app_id)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT project_id, student_id FROM applications WHERE id=%s", (app_id_str,))
    app_data = cur.fetchone()
    if not app_data:
        flash('Заявка не найдена.', 'error')
        return redirect(request.referrer or url_for('my_projects'))
    project_id = app_data['project_id']
    student_id = app_data['student_id']
    cur.execute("SELECT id_tutor, max_students FROM projects WHERE id=%s", (project_id,))
    project = cur.fetchone()
    if not project or project['id_tutor'] != session['user_id']:
        flash('Нет прав на изменение этой заявки.', 'error')
        return redirect(request.referrer or url_for('my_projects'))
    if status == 'accepted':
        cur.execute("SELECT COUNT(*) AS cnt FROM applications WHERE project_id=%s AND status='accepted'", (project_id,))
        accepted_count = cur.fetchone()['cnt']
        if accepted_count >= project['max_students']:
            flash(f'Невозможно принять: проект уже набрал {accepted_count} из {project["max_students"]} студентов.',
                  'error')
            return redirect(request.referrer or url_for('my_projects'))
    cur.execute("""
        UPDATE applications SET status=%s, updated_at=NOW()
        WHERE id=%s
    """, (status, app_id_str))
    conn.commit()
    if status == 'accepted':
        ensure_project_chat(project_id, project['id_tutor'], student_id)
        log_action(session['user_id'], 'accept_application', f'Принята заявка {app_id}')
        flash(f'Заявка принята. Студент добавлен в групповой чат проекта.', 'success')
    else:
        log_action(session['user_id'], 'reject_application', f'Отклонена заявка {app_id}')
        flash('Заявка отклонена.', 'success')
    cur.close()
    conn.close()
    return redirect(request.referrer or url_for('my_projects'))


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        about = request.form.get('about', '')
        cur.execute("UPDATE users SET about=%s, updated_at=NOW() WHERE id=%s", (about, session['user_id']))
        conn.commit()
        flash('Информация обновлена.', 'success')
        log_action(session['user_id'], 'update_profile', 'Изменено поле about')

    # Добавляем рейтинг
    cur.execute("""
        SELECT u.id, u.email, u.first_name AS name, u.last_name AS surname, 
               u.about, u.role, u.created_at, u.avatar_url,
               COALESCE(AVG(r.rating), 0) AS rating
        FROM users u
        LEFT JOIN reviews r ON r.recipient_id = u.id
        WHERE u.id = %s
        GROUP BY u.id, u.email, u.first_name, u.last_name, u.about, u.role, u.created_at, u.avatar_url
    """, (session['user_id'],))
    user = cur.fetchone()

    student_info = None
    active_projects = 0
    completed_projects = 0
    total_applications = 0
    projects_count = 0

    if session['role'] == 'student':
        cur.execute("SELECT course FROM students WHERE user_id=%s", (session['user_id'],))
        std = cur.fetchone()
        student_info = std['course'] if std else None
        cur.execute("""
            SELECT COUNT(*) AS cnt FROM applications a
            JOIN projects p ON a.project_id = p.id
            WHERE a.student_id=%s AND a.status='accepted' AND p.status='открыт'
        """, (session['user_id'],))
        row = cur.fetchone()
        active_projects = row['cnt'] if row else 0
        cur.execute("""
            SELECT COUNT(*) AS cnt FROM applications a
            JOIN projects p ON a.project_id = p.id
            WHERE a.student_id=%s AND a.status='accepted' AND p.status='завершён'
        """, (session['user_id'],))
        row = cur.fetchone()
        completed_projects = row['cnt'] if row else 0
        cur.execute("SELECT COUNT(*) AS cnt FROM applications WHERE student_id=%s", (session['user_id'],))
        row = cur.fetchone()
        total_applications = row['cnt'] if row else 0
    else:
        cur.execute("SELECT COUNT(*) AS cnt FROM projects WHERE id_tutor=%s", (session['user_id'],))
        row = cur.fetchone()
        projects_count = row['cnt'] if row else 0
        cur.execute("""
            SELECT COUNT(*) AS cnt FROM projects p
            JOIN applications a ON p.id = a.project_id
            WHERE p.id_tutor=%s AND a.status='accepted' AND p.status='завершён'
        """, (session['user_id'],))
        row = cur.fetchone()
        completed_projects = row['cnt'] if row else 0

    cur.close()
    conn.close()

    return render_template('profile.html', user=user, student_info=student_info,
                           active_projects=active_projects, completed_projects=completed_projects,
                           total_applications=total_applications, projects_count=projects_count)


@app.route('/upload_avatar', methods=['POST'])
def upload_avatar():
    if 'avatar' not in request.files:
        flash('Нет файла для загрузки', 'error')
        return redirect(url_for('profile'))

    file = request.files['avatar']
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        unique_name = f"{uuid.uuid4().hex}_{filename}"
        filepath = os.path.join(app.config['AVATAR_FOLDER'], unique_name)
        file.save(filepath)
        avatar_url = f"avatars/{unique_name}"

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET avatar_url=%s WHERE id=%s", (avatar_url, session['user_id']))
        conn.commit()
        cur.close()
        conn.close()

        flash('Аватар успешно загружен!', 'success')
    else:
        flash('Неверный формат файла', 'error')
    return redirect(url_for('profile'))


@app.route('/my_applications')
def my_applications():
    if session['role'] != 'student':
        flash('Только для студентов.', 'error')
        return redirect(url_for('profile'))
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT a.id, a.status, a.applied_at, p.id AS project_id, p.title
        FROM applications a
        JOIN projects p ON a.project_id = p.id
        WHERE a.student_id = %s
        ORDER BY a.applied_at DESC
    """, (session['user_id'],))
    apps = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('my_applications.html', apps=apps)


@app.route('/reviews', methods=['GET', 'POST'])
def reviews():
    conn = get_db_connection()
    cur = conn.cursor()
    if request.method == 'POST':
        recipient_id = request.form['recipient_id']
        rating = int(request.form['rating'])
        comment = request.form.get('comment', '')
        if recipient_id == session['user_id']:
            flash('Нельзя оставить отзыв самому себе.', 'error')
            return redirect(url_for('reviews'))
        cur.execute("SELECT 1 FROM reviews WHERE author_id=%s AND recipient_id=%s",
                    (session['user_id'], recipient_id))
        if cur.fetchone():
            flash('Вы уже оставляли отзыв этому пользователю.', 'warning')
        else:
            cur.execute("""
                INSERT INTO reviews (id, author_id, recipient_id, rating, comment, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
            """, (str(uuid.uuid4()), session['user_id'], recipient_id, rating, comment))
            conn.commit()
            log_action(session['user_id'], 'add_review', f'Отзыв для {recipient_id}')
            flash('Отзыв отправлен!', 'success')
        return redirect(url_for('reviews'))
    if session['role'] == 'student':
        cur.execute("SELECT id, first_name AS name, last_name AS surname, avatar_url FROM users WHERE role='teacher'")
    else:
        cur.execute("SELECT id, first_name AS name, last_name AS surname, avatar_url FROM users WHERE role='student'")
    recipients = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('reviews.html', recipients=recipients)


@app.route('/view_reviews/<uuid:user_id>')
def view_reviews(user_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT r.rating, r.comment, r.created_at,
               u.first_name AS name, u.last_name AS surname, u.avatar_url
        FROM reviews r
        JOIN users u ON r.author_id = u.id
        WHERE r.recipient_id = %s
        ORDER BY r.created_at DESC
    """, (str(user_id),))
    reviews_list = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('view_reviews.html', reviews=reviews_list)


# ----- ЧАТЫ -----
@app.route('/chats')
def chats_list():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT c.id, c.name, c.last_message,
               (SELECT COUNT(*) FROM messages m WHERE m.chat_id = c.id AND m.is_read = FALSE AND m.sender_id != %s) AS unread
        FROM chats c
        JOIN chat_members cm ON c.id = cm.chat_id
        WHERE cm.user_id = %s
        ORDER BY c.updated_at DESC
    """, (session['user_id'], session['user_id']))
    chats = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('chats_list.html', chats=chats)


@app.route('/chat/<uuid:chat_id>')
def chat(chat_id):
    chat_id_str = str(chat_id)
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM chat_members WHERE chat_id=%s AND user_id=%s", (chat_id_str, session['user_id']))
    if not cur.fetchone():
        flash('Нет доступа к этому чату.', 'error')
        return redirect(url_for('chats_list'))
    cur.execute("SELECT name FROM chats WHERE id=%s", (chat_id_str,))
    chat_row = cur.fetchone()
    chat_name = chat_row['name'] if chat_row else 'Чат'
    cur.execute("""
        SELECT m.id, m.content, m.sent_at, m.sender_id,
               u.first_name AS name, u.last_name AS surname, u.avatar_url,
               COALESCE(json_agg(DISTINCT jsonb_build_object('id', ma.id, 'file_url', ma.file_url, 'file_name', ma.file_name, 'file_size', ma.file_size)) FILTER (WHERE ma.id IS NOT NULL), '[]') AS attachments
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        LEFT JOIN message_attachments ma ON m.id = ma.message_id
        WHERE m.chat_id = %s
        GROUP BY m.id, u.id
        ORDER BY m.sent_at
    """, (chat_id_str,))
    messages = cur.fetchall()
    cur.execute("""
        UPDATE messages SET is_read = TRUE
        WHERE chat_id = %s AND sender_id != %s
    """, (chat_id_str, session['user_id']))
    conn.commit()
    cur.close()
    conn.close()
    return render_template('chat.html', chat_id=chat_id, chat_name=chat_name, messages=messages)


@app.route('/send_message/<uuid:chat_id>', methods=['POST'])
def send_message(chat_id):
    chat_id_str = str(chat_id)
    content = request.form.get('content', '').strip()
    if not content:
        flash('Сообщение не может быть пустым.', 'error')
        return redirect(url_for('chat', chat_id=chat_id))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT 1 FROM chat_members WHERE chat_id=%s AND user_id=%s", (chat_id_str, session['user_id']))
        if not cur.fetchone():
            flash('Нет доступа.', 'error')
            return redirect(url_for('chats_list'))

        msg_id = str(uuid.uuid4())
        cur.execute("""
            INSERT INTO messages (id, chat_id, sender_id, content, is_read, sent_at, updated_at)
            VALUES (%s, %s, %s, %s, FALSE, NOW(), NOW())
        """, (msg_id, chat_id_str, session['user_id'], content))

        attachments = request.files.getlist('attachments')
        for attachment in attachments:
            if attachment and allowed_file(attachment.filename):
                filename = secure_filename(attachment.filename)
                unique_name = f"{uuid.uuid4().hex}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                attachment.save(filepath)
                file_url = f"uploads/{unique_name}"
                file_size = os.path.getsize(filepath)
                cur.execute("""
                    INSERT INTO message_attachments (id, message_id, file_url, file_name, file_size, created_at)
                    VALUES (%s, %s, %s, %s, %s, NOW())
                """, (str(uuid.uuid4()), msg_id, file_url, filename, file_size))

        cur.execute("UPDATE chats SET last_message=%s, updated_at=NOW() WHERE id=%s", (content[:255], chat_id_str))
        conn.commit()
        flash('Сообщение отправлено', 'success')
    except Exception as e:
        conn.rollback()
        print(f"Ошибка при отправке сообщения: {e}")
        flash(f'Ошибка при отправке: {e}', 'error')
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('chat', chat_id=chat_id))


# ----- АДМИН-ПАНЕЛЬ -----
@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")
    users_cnt = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) FROM projects")
    projects_cnt = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) FROM applications")
    apps_cnt = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) FROM reviews")
    reviews_cnt = cur.fetchone()['count']
    cur.close()
    conn.close()
    return render_template('admin/dashboard.html', users_cnt=users_cnt, projects_cnt=projects_cnt,
                           apps_cnt=apps_cnt, reviews_cnt=reviews_cnt)


@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT u.id, u.first_name AS name, u.last_name AS surname, u.email, u.role, u.avatar_url,
               COALESCE(AVG(r.rating), 0) AS rating
        FROM users u
        LEFT JOIN reviews r ON r.recipient_id = u.id
        GROUP BY u.id, u.first_name, u.last_name, u.email, u.role, u.avatar_url
        ORDER BY u.created_at
    """)
    users = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin/users.html', users=users)


@app.route('/admin/delete_user/<uuid:user_id>')
@admin_required
def admin_delete_user(user_id):
    user_id_str = str(user_id)
    if user_id_str == session['user_id']:
        flash('Нельзя удалить самого себя.', 'error')
        return redirect(url_for('admin_users'))

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # 1. Удаляем вложения из сообщений пользователя
        cur.execute("""
            DELETE FROM message_attachments 
            WHERE message_id IN (
                SELECT id FROM messages WHERE sender_id = %s
            )
        """, (user_id_str,))

        # 2. Удаляем сообщения пользователя
        cur.execute("DELETE FROM messages WHERE sender_id = %s", (user_id_str,))

        # 3. Удаляем пользователя из чатов
        cur.execute("DELETE FROM chat_members WHERE user_id = %s", (user_id_str,))

        # 4. Удаляем чаты, в которых не осталось участников
        cur.execute("""
            DELETE FROM chats 
            WHERE id IN (
                SELECT c.id 
                FROM chats c
                LEFT JOIN chat_members cm ON c.id = cm.chat_id
                WHERE c.id IN (
                    SELECT chat_id FROM chat_members WHERE user_id = %s
                )
                GROUP BY c.id
                HAVING COUNT(cm.user_id) = 0
            )
        """, (user_id_str,))

        # 5. Удаляем заявки пользователя
        cur.execute("DELETE FROM applications WHERE student_id = %s", (user_id_str,))

        # 6. Удаляем проекты пользователя (как преподавателя)
        cur.execute("SELECT id FROM projects WHERE id_tutor = %s", (user_id_str,))
        projects = cur.fetchall()
        for project in projects:
            project_id_str = str(project['id'])
            # Удаляем изображения проектов
            cur.execute("DELETE FROM images WHERE entity_type='project' AND entity_id=%s", (project_id_str,))
            # Удаляем заявки на проекты
            cur.execute("DELETE FROM applications WHERE project_id=%s", (project_id_str,))
        # Удаляем проекты
        cur.execute("DELETE FROM projects WHERE id_tutor = %s", (user_id_str,))

        # 7. Удаляем отзывы (где пользователь автор или получатель)
        cur.execute("DELETE FROM reviews WHERE author_id = %s OR recipient_id = %s", (user_id_str, user_id_str))

        # 8. Удаляем записи из дополнительных таблиц
        cur.execute("DELETE FROM students WHERE user_id = %s", (user_id_str,))
        cur.execute("DELETE FROM teachers WHERE user_id = %s", (user_id_str,))
        cur.execute("DELETE FROM admins WHERE user_id = %s", (user_id_str,))

        # 9. Удаляем логи пользователя
        cur.execute("DELETE FROM logs WHERE user_id = %s", (user_id_str,))

        # 10. Наконец, удаляем самого пользователя
        cur.execute("DELETE FROM users WHERE id = %s", (user_id_str,))

        conn.commit()
        log_action(session['user_id'], 'delete_user', f'Удалён пользователь {user_id}')
        flash('Пользователь и все связанные данные успешно удалены.', 'success')

    except Exception as e:
        conn.rollback()
        flash(f'Ошибка при удалении: {e}', 'error')
        print(f"Ошибка удаления пользователя: {e}")
        import traceback
        traceback.print_exc()
    finally:
        cur.close()
        conn.close()

    return redirect(url_for('admin_users'))


@app.route('/admin/add_user', methods=['GET', 'POST'])
@admin_required
def admin_add_user():
    if request.method == 'POST':
        email = request.form['email']
        name = request.form['name']
        surname = request.form['surname']
        role = request.form['role']
        password = request.form['password']
        hashed = generate_password_hash(password)
        user_id = str(uuid.uuid4())
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO users (id, email, password_hash, first_name, last_name, role, is_active, is_verified, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, TRUE, TRUE, NOW(), NOW())
            """, (user_id, email, hashed, name, surname, role))
            if role == 'teacher':
                position = request.form.get('position', 'Преподаватель')
                cur.execute("""
                    INSERT INTO teachers (user_id, position, created_at, updated_at)
                    VALUES (%s, %s, NOW(), NOW())
                """, (user_id, position))
            elif role == 'admin':
                cur.execute("""
                    INSERT INTO admins (user_id, admin_level, created_at, updated_at)
                    VALUES (%s, 1, NOW(), NOW())
                """, (user_id,))
            conn.commit()
            log_action(session['user_id'], 'add_user', f'Создан {role}: {email}')
            flash(f'Пользователь {email} создан.', 'success')
        except Exception as e:
            conn.rollback()
            flash(f'Ошибка: {e}', 'error')
        finally:
            cur.close()
            conn.close()
        return redirect(url_for('admin_users'))
    return render_template('admin/add_user.html')


@app.route('/admin/topics')
@admin_required
def admin_topics():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM topics ORDER BY name")
    topics = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin/topics.html', topics=topics)


@app.route('/admin/add_topic', methods=['POST'])
@admin_required
def admin_add_topic():
    name = request.form['name'].strip()
    if name:
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO topics (name, created_at) VALUES (%s, NOW()) RETURNING id", (name,))
            conn.commit()
            flash('Тема добавлена.', 'success')
        except Exception as e:
            flash('Такая тема уже существует.', 'error')
        finally:
            cur.close()
            conn.close()
    return redirect(url_for('admin_topics'))


@app.route('/admin/delete_topic/<int:topic_id>')
@admin_required
def admin_delete_topic(topic_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM topics WHERE id=%s", (topic_id,))
    conn.commit()
    flash('Тема удалена.', 'success')
    cur.close()
    conn.close()
    return redirect(url_for('admin_topics'))


@app.route('/admin/news')
@admin_required
def admin_news_list():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, title, content, image_url, published_at, 
                   COALESCE(type, 'news') as type
            FROM news_feed 
            ORDER BY published_at DESC
        """)
        news = cur.fetchall()
    except Exception as e:
        print(f"Ошибка: {e}")
        news = []
    finally:
        cur.close()
        conn.close()
    return render_template('admin/news_list.html', news=news)


@app.route('/admin/add_news', methods=['GET', 'POST'])
@admin_required
def admin_add_news():
    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        content = request.form.get('content', '').strip()
        news_type = request.form.get('news_type', 'news')
        event_date = request.form.get('event_date') or None
        event_location = request.form.get('event_location') or None

        if not title or not content:
            flash('Заголовок и содержание обязательны!', 'error')
            return redirect(url_for('admin_add_news'))

        # Обработка изображений
        image_urls = []
        images = request.files.getlist('images')
        for img in images:
            if img and allowed_file(img.filename):
                filename = secure_filename(img.filename)
                unique_name = f"{uuid.uuid4().hex}_{filename}"
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                img.save(filepath)
                image_urls.append(f"uploads/{unique_name}")

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO news_feed (id, type, title, content, image_url, 
                                       event_date, event_location,
                                       published_at, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), NOW())
            """, (str(uuid.uuid4()), news_type, title, content,
                  ','.join(image_urls) if image_urls else None,
                  event_date, event_location))

            conn.commit()
            log_action(session['user_id'], 'add_news', f'{news_type}: {title}')
            flash('Публикация успешно добавлена!', 'success')
            return redirect(url_for('admin_news_list'))

        except Exception as e:
            conn.rollback()
            flash(f'Ошибка при добавлении: {str(e)}', 'error')
            print(f"Ошибка: {e}")
        finally:
            cur.close()
            conn.close()

    return render_template('admin/add_news.html')


@app.route('/admin/delete_news/<uuid:news_id>')
@admin_required
def admin_delete_news(news_id):
    news_id_str = str(news_id)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Удаляем связанные изображения
        cur.execute("SELECT image_url FROM news_feed WHERE id=%s", (news_id_str,))
        news = cur.fetchone()
        if news and news['image_url']:
            for img_url in news['image_url'].split(','):
                if img_url:
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], img_url.replace('uploads/', ''))
                    if os.path.exists(filepath):
                        os.remove(filepath)

        cur.execute("DELETE FROM news_feed WHERE id=%s", (news_id_str,))
        conn.commit()
        log_action(session['user_id'], 'delete_news', f'Удалена публикация {news_id}')
        flash('Публикация удалена.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Ошибка при удалении: {e}', 'error')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('admin_news_list'))


@app.route('/admin/projects')
@admin_required
def admin_projects():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("""
        SELECT p.id, p.title, p.status, p.created_at, p.max_students,
               u.first_name AS tutor_name, u.last_name AS tutor_surname,
               (SELECT COUNT(*) FROM applications WHERE project_id=p.id) AS apps_count
        FROM projects p
        JOIN users u ON p.id_tutor = u.id
        ORDER BY p.created_at DESC
    """)
    projects = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin/projects.html', projects=projects)


@app.route('/admin/delete_project/<uuid:project_id>')
@admin_required
def admin_delete_project(project_id):
    project_id_str = str(project_id)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT image_url FROM images WHERE entity_type='project' AND entity_id=%s", (project_id_str,))
        images = cur.fetchall()
        for img in images:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], img['image_url'].replace('uploads/', ''))
            if os.path.exists(filepath):
                os.remove(filepath)

        cur.execute("DELETE FROM images WHERE entity_type='project' AND entity_id=%s", (project_id_str,))
        cur.execute("DELETE FROM applications WHERE project_id=%s", (project_id_str,))
        cur.execute("DELETE FROM projects WHERE id=%s", (project_id_str,))
        conn.commit()
        log_action(session['user_id'], 'admin_delete_project', f'Удалён проект {project_id}')
        flash('Проект удалён.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Ошибка при удалении: {e}', 'error')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('admin_projects'))


@app.route('/teacher/delete_project/<uuid:project_id>')
@teacher_required
def teacher_delete_project(project_id):
    project_id_str = str(project_id)
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id_tutor FROM projects WHERE id=%s", (project_id_str,))
        project = cur.fetchone()
        if not project or project['id_tutor'] != session['user_id']:
            flash('Нет прав на удаление этого проекта.', 'error')
            return redirect(url_for('my_projects'))

        cur.execute("SELECT image_url FROM images WHERE entity_type='project' AND entity_id=%s", (project_id_str,))
        images = cur.fetchall()
        for img in images:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], img['image_url'].replace('uploads/', ''))
            if os.path.exists(filepath):
                os.remove(filepath)

        cur.execute("DELETE FROM images WHERE entity_type='project' AND entity_id=%s", (project_id_str,))
        cur.execute("DELETE FROM applications WHERE project_id=%s", (project_id_str,))
        cur.execute("DELETE FROM projects WHERE id=%s", (project_id_str,))
        conn.commit()
        log_action(session['user_id'], 'teacher_delete_project', f'Удалён проект {project_id}')
        flash('Проект удалён.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Ошибка при удалении: {e}', 'error')
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('my_projects'))


@app.route('/admin/query', methods=['GET', 'POST'])
@admin_required
def admin_query():
    result = None
    error = None
    if request.method == 'POST':
        query = request.form.get('query', '').strip()
        if not query:
            error = "❌ Запрос не может быть пустым."
        else:
            dangerous_keywords = ['DROP', 'DELETE', 'UPDATE', 'INSERT', 'ALTER',
                                  'TRUNCATE', 'CREATE', 'REPLACE', 'MERGE']
            query_upper = query.upper()
            if not query_upper.startswith('SELECT'):
                error = "❌ Разрешены только SELECT-запросы. Изменение данных запрещено."
            else:
                tokens = query_upper.split()
                if any(kw in tokens for kw in dangerous_keywords):
                    error = "❌ Запрос содержит запрещённые ключевые слова."
                else:
                    try:
                        conn = get_db_connection()
                        cur = conn.cursor()
                        cur.execute(query)
                        result = cur.fetchall()
                        cur.close()
                        conn.close()
                    except Exception as e:
                        error = f"Ошибка выполнения SQL: {str(e)}"
    return render_template('admin/query.html', result=result, error=error)


@app.route('/admin/logs')
@admin_required
def admin_logs():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY created_at DESC LIMIT 200")
    logs = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('admin/logs.html', logs=logs)


# ----- АУТЕНТИФИКАЦИЯ -----
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, password_hash, first_name, last_name, role, avatar_url FROM users WHERE email=%s",
            (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['user_name'] = f"{user['first_name']} {user['last_name']}"
            session['role'] = user['role']
            log_action(user['id'], 'login', 'Вход в систему')
            flash('Добро пожаловать!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный email или пароль.', 'error')
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        faculty = request.form.get('faculty', '')
        group_number = request.form.get('group_number', '')
        course = request.form['course']
        password = request.form['password']
        hashed = generate_password_hash(password)
        user_id = str(uuid.uuid4())
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO users (id, email, password_hash, first_name, last_name, group_number, course, role, is_active, is_verified, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, 'student', TRUE, FALSE, NOW(), NOW())
            """, (user_id, email, hashed, first_name, last_name, group_number, course))
            student_id_number = f"STU{datetime.now().strftime('%Y%m%d')}{user_id[:4]}"
            cur.execute("""
                INSERT INTO students (user_id, student_id, course, created_at, updated_at)
                VALUES (%s, %s, %s, NOW(), NOW())
            """, (user_id, student_id_number, course))
            conn.commit()
            session['user_id'] = user_id
            session['user_name'] = f"{first_name} {last_name}"
            session['role'] = 'student'
            log_action(user_id, 'register', 'Регистрация студента')
            flash('Регистрация успешна! Добро пожаловать.', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            conn.rollback()
            flash(f'Ошибка: {e}', 'error')
        finally:
            cur.close()
            conn.close()
    return render_template('register.html')


@app.route('/logout')
def logout():
    if 'user_id' in session:
        log_action(session['user_id'], 'logout', 'Выход из системы')
    session.clear()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))


# ----- API -----
def api_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            verify_jwt_in_request()
            return f(*args, **kwargs)
        except:
            return jsonify({"error": "Требуется авторизация (JWT)"}), 401

    return decorated


# маршруты апи
@app.route('/api/v1/register', methods=['POST'])
def api_register():
    data = request.get_json() or {}
    first_name = data.get("first_name") or data.get("name")
    last_name = data.get("last_name") or data.get("surname")
    email = data.get("email")
    password = data.get("password")
    course = data.get("course")
    group_number = data.get("group_number")

    if not email or not password:
        return jsonify({"error": "Email и пароль обязательны"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        if cur.fetchone():
            return jsonify({"error": "Пользователь с таким email уже существует"}), 409

        hashed = generate_password_hash(password)
        user_id = str(uuid.uuid4())

        cur.execute("""
            INSERT INTO users (id, email, password_hash, first_name, last_name, 
                             course, group_number, role, is_active, is_verified, created_at, updated_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'student', TRUE, FALSE, NOW(), NOW())
            RETURNING id
        """, (user_id, email, hashed, first_name, last_name, course, group_number))

        cur.execute("""
            INSERT INTO students (user_id, student_id, course, created_at, updated_at)
            VALUES (%s, %s, %s, NOW(), NOW())
        """, (user_id, f"STU{datetime.now().strftime('%Y%m%d')}{str(uuid.uuid4())[:4]}", course))

        conn.commit()

        token = create_access_token(identity=user_id)
        return jsonify({
            "message": "Регистрация успешна",
            "token": token,
            "user": {
                "id": user_id,
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "role": "student"
            }
        }), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email и пароль обязательны"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id, password_hash, role FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({"error": "Неверные данные"}), 401

        token = create_access_token(identity=str(user['id']))
        return jsonify({
            "message": "Вход выполнен",
            "token": token,
            "role": user['role']
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/profile', methods=['GET'], strict_slashes=False)
@api_login_required
def api_profile():
    user_id = get_jwt_identity()
    print(f"[PROFILE] JWT user_id: {user_id}")

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, email, first_name, last_name, role, about, avatar_url,
                   created_at, course, group_number
            FROM users WHERE id = %s
        """, (user_id,))
        user = cur.fetchone()

        if user:
            return jsonify(dict(user)), 200
        else:
            return jsonify({"error": "User not found"}), 404
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/topics', methods=['GET'], strict_slashes=False)
def api_get_topics():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, name
            FROM topics
            ORDER BY name
        """)
        rows = cur.fetchall()
        return jsonify([dict(r) for r in rows]), 200
    except Exception as e:
        print(f"[ERROR] get_topics: {e}")
        return jsonify({"error": "Не удалось загрузить темы"}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/projects', methods=['POST'])
@api_login_required
def api_create_project():
    user_id = get_jwt_identity()

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
        user_role = cur.fetchone()
        if not user_role or user_role['role'] not in ('teacher', 'admin'):
            return jsonify({"error": "Только преподаватели могут создавать проекты"}), 403
    finally:
        cur.close()
        conn.close()

    if request.is_json:
        data = request.get_json() or {}
    else:
        data = request.form.to_dict()

    title = data.get('title')
    description = data.get('description')
    requirements = data.get('requirements', '')
    details = data.get('details', '')
    topic_id = data.get('topic_id')
    difficulty = data.get('difficulty', 'средний')
    deadline = data.get('deadline')
    max_students = data.get('max_students', 1)

    if not title or not description:
        return jsonify({"error": "title и description обязательны"}), 400

    try:
        max_students = int(max_students)
        if max_students < 1:
            max_students = 1
    except:
        max_students = 1

    project_id = str(uuid.uuid4())

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO projects (
                id, id_tutor, title, description, requirements, details,
                topic_id, difficulty, deadline, status, max_students,
                created_at, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, 'открыт', %s, NOW(), NOW()
            )
            RETURNING id, title, description, difficulty, deadline, max_students, status
        """, (
            project_id, user_id, title, description, requirements, details,
            topic_id, difficulty, deadline, max_students
        ))

        new_project = cur.fetchone()

        if request.files:
            images = request.files.getlist('images')
            for idx, img in enumerate(images):
                if img and allowed_file(img.filename):
                    filename = secure_filename(img.filename)
                    unique_name = f"{uuid.uuid4().hex}_{filename}"
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                    img.save(filepath)
                    image_url = f"uploads/{unique_name}"

                    cur.execute("""
                        INSERT INTO images (
                            id, entity_type, entity_id, image_url, image_type, 
                            sort_order, is_active, created_at, updated_at
                        ) VALUES (%s, 'project', %s, %s, 'main', %s, TRUE, NOW(), NOW())
                    """, (str(uuid.uuid4()), project_id, image_url, idx))

        conn.commit()
        log_action(user_id, 'add_project', f'Создан проект через API: {title}')

        return jsonify(dict(new_project)), 201

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/v1/profile', methods=['PATCH'], strict_slashes=False)
@api_login_required
def api_update_profile():
    user_id = get_jwt_identity()
    data = request.get_json(silent=True) or {}
 
    set_parts = []
    values = []

    if 'about' in data and data['about'] is not None:
        about = data['about']
        if not isinstance(about, str):
            return jsonify({"error": "Поле 'about' должно быть строкой"}), 400
        if len(about) > 500:
            return jsonify({"error": "Поле 'about' не может быть длиннее 500 символов"}), 400
        set_parts.append("about = %s")
        values.append(about.strip())

    if 'first_name' in data and data['first_name'] is not None:
        first_name = data['first_name']
        if not isinstance(first_name, str) or not first_name.strip():
            return jsonify({"error": "Поле 'first_name' не может быть пустым"}), 400
        if len(first_name) > 100:
            return jsonify({"error": "Имя слишком длинное"}), 400
        set_parts.append("first_name = %s")
        values.append(first_name.strip())

    if 'last_name' in data and data['last_name'] is not None:
        last_name = data['last_name']
        if not isinstance(last_name, str) or not last_name.strip():
            return jsonify({"error": "Поле 'last_name' не может быть пустым"}), 400
        if len(last_name) > 100:
            return jsonify({"error": "Фамилия слишком длинная"}), 400
        set_parts.append("last_name = %s")
        values.append(last_name.strip())
 
    if 'course' in data and data['course'] is not None and str(data['course']).strip() != '':
        try:
            course = int(data['course'])
        except (TypeError, ValueError):
            return jsonify({"error": "Поле 'course' должно быть числом"}), 400
        set_parts.append("course = %s")
        values.append(course)

    if 'group_number' in data and data['group_number'] is not None:
        group_number = str(data['group_number']).strip()
        if len(group_number) > 50:
            return jsonify({"error": "Номер группы слишком длинный"}), 400
        set_parts.append("group_number = %s")
        values.append(group_number if group_number != '' else None)

    if 'avatar_url' in data and data['avatar_url'] is not None:
        avatar_url = str(data['avatar_url']).strip()
        if len(avatar_url) > 500:
            return jsonify({"error": "avatar_url слишком длинный"}), 400
        set_parts.append("avatar_url = %s")
        values.append(avatar_url if avatar_url != '' else None)
 
    if not set_parts:
        return jsonify({"error": "Нет полей для обновления"}), 400
 
    set_parts.append("updated_at = NOW()")
 
    query = f"""
        UPDATE users
        SET {', '.join(set_parts)}
        WHERE id = %s
        RETURNING id, email, first_name, last_name, role, about,
                  avatar_url, created_at, course, group_number
    """
    values.append(user_id)
 
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(query, tuple(values))
        updated_user = cur.fetchone()
 
        if not updated_user:
            return jsonify({"error": "Пользователь не найден"}), 404
 
        conn.commit()
        log_action(user_id, 'update_profile', 'Обновлён профиль через API')
        return jsonify(dict(updated_user)), 200
 
    except Exception as e:
        conn.rollback()
        print(f"[ERROR] Profile update: {e}")
        return jsonify({"error": "Внутренняя ошибка сервера"}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/v1/news', methods=['GET'], strict_slashes=False)
def api_get_news():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id,
                   title,
                   content AS description,
                   image_url,
                   published_at
            FROM news_feed
            WHERE type = 'news'
            ORDER BY COALESCE(published_at, created_at) DESC
        """)
        rows = cur.fetchall()
        return jsonify([dict(r) for r in rows]), 200
    except Exception as e:
        print(f"[ERROR] get_news: {e}")
        return jsonify({"error": "Не удалось загрузить новости"}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/v1/reviews/<recipient_id>', methods=['GET'], strict_slashes=False)
def api_get_reviews(recipient_id):
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT r.id,
                   r.author_id,
                   r.rating,
                   r.comment AS text,
                   r.created_at,
                   COALESCE(u.first_name || ' ' || u.last_name, 'Аноним') AS author_name
            FROM reviews r
            LEFT JOIN users u ON r.author_id = u.id
            WHERE r.recipient_id = %s
            ORDER BY r.created_at DESC
        """, (recipient_id,))
        rows = cur.fetchall()
        return jsonify([dict(r) for r in rows]), 200
    except Exception as e:
        print(f"[ERROR] get_reviews: {e}")
        return jsonify({"error": "Не удалось загрузить отзывы"}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/reviews/<recipient_id>', methods=['POST'], strict_slashes=False)
@api_login_required
def api_create_or_update_review(recipient_id):
    author_id = get_jwt_identity()

    # Нельзя оставлять отзыв самому себе
    if str(author_id) == str(recipient_id):
        return jsonify({"error": "Нельзя оставить отзыв самому себе"}), 400

    data = request.get_json(silent=True) or {}
    rating = data.get('rating')
    text = data.get('text')

    # Валидация рейтинга
    try:
        rating = int(rating)
    except (TypeError, ValueError):
        return jsonify({"error": "rating должен быть целым числом от 1 до 5"}), 400

    if rating < 1 or rating > 5:
        return jsonify({"error": "rating должен быть от 1 до 5"}), 400

    # Валидация текста
    if not text or not isinstance(text, str) or not text.strip():
        return jsonify({"error": "Поле text обязательно"}), 400

    if len(text) > 1000:
        return jsonify({"error": "Отзыв не может быть длиннее 1000 символов"}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT id FROM users WHERE id = %s", (recipient_id,))
        if not cur.fetchone():
            return jsonify({"error": "Пользователь не найден"}), 404
            
        cur.execute("""
            SELECT id FROM reviews
            WHERE author_id = %s AND recipient_id = %s
        """, (author_id, recipient_id))
        existing = cur.fetchone()

        if existing:
            cur.execute("""
                UPDATE reviews
                SET rating = %s, comment = %s, updated_at = NOW()
                WHERE id = %s
                RETURNING id, author_id, rating, comment AS text, created_at
            """, (rating, text.strip(), existing['id']))
            status_code = 200
            log_msg = f'Обновлён отзыв пользователю {recipient_id}'
        else:
            review_id = str(uuid.uuid4())
            cur.execute("""
                INSERT INTO reviews (id, author_id, recipient_id, rating, comment,
                                     created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                RETURNING id, author_id, rating, comment AS text, created_at
            """, (review_id, author_id, recipient_id, rating, text.strip()))
            status_code = 201
            log_msg = f'Создан отзыв пользователю {recipient_id}'

        saved_review = cur.fetchone()

        cur.execute("""
            SELECT COALESCE(first_name || ' ' || last_name, 'Аноним') AS author_name
            FROM users WHERE id = %s
        """, (author_id,))
        author_row = cur.fetchone()

        conn.commit()
        log_action(author_id, 'review', log_msg)

        result = dict(saved_review)
        result['author_name'] = author_row['author_name'] if author_row else 'Аноним'

        return jsonify(result), status_code

    except Exception as e:
        conn.rollback()
        print(f"[ERROR] create_or_update_review: {e}")
        return jsonify({"error": "Не удалось сохранить отзыв"}), 500
    finally:
        cur.close()
        conn.close()


@app.route('/api/v1/reviews/<recipient_id>', methods=['DELETE'], strict_slashes=False)
@api_login_required
def api_delete_review(recipient_id):
    author_id = get_jwt_identity()

    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            DELETE FROM reviews
            WHERE author_id = %s AND recipient_id = %s
            RETURNING id
        """, (author_id, recipient_id))
        deleted = cur.fetchone()

        if not deleted:
            return jsonify({"error": "Отзыв не найден"}), 404

        conn.commit()
        log_action(author_id, 'review', f'Удалён отзыв пользователю {recipient_id}')
        return jsonify({"message": "Отзыв удалён"}), 200

    except Exception as e:
        conn.rollback()
        print(f"[ERROR] delete_review: {e}")
        return jsonify({"error": "Не удалось удалить отзыв"}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/v1/users', methods=['GET'], strict_slashes=False)
@api_login_required
def api_list_users():
    user_id = get_jwt_identity()
    role_filter = request.args.get('role')
 
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        if not role_filter:
            cur.execute("SELECT role FROM users WHERE id = %s", (user_id,))
            me = cur.fetchone()
            my_role = me['role'] if me else 'student'
            role_filter = 'student' if my_role in ('teacher', 'admin') else 'teacher'
 
        if role_filter not in ('student', 'teacher', 'admin'):
            return jsonify({"error": "Недопустимая роль"}), 400
 
        cur.execute("""
            SELECT id,
                   first_name,
                   last_name,
                   COALESCE(first_name || ' ' || last_name, email) AS full_name,
                   role,
                   course,
                   group_number,
                   avatar_url,
                   rating
            FROM users
            WHERE role = %s
              AND id <> %s
              AND is_active = TRUE
            ORDER BY first_name, last_name
        """, (role_filter, user_id))
 
        rows = cur.fetchall()
        return jsonify([dict(r) for r in rows]), 200
 
    except Exception as e:
        print(f"[ERROR] list_users: {e}")
        return jsonify({"error": "Не удалось загрузить список пользователей"}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/api/v1/topics', methods=['GET'], strict_slashes=False)
def api_get_topics():
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("""
            SELECT id, name
            FROM topics
            ORDER BY name
        """)
        rows = cur.fetchall()
        return jsonify([dict(r) for r in rows]), 200
    except Exception as e:
        print(f"[ERROR] get_topics: {e}")
        return jsonify({"error": "Не удалось загрузить темы"}), 500
    finally:
        cur.close()
        conn.close()

# ----- Запуск -----
if __name__ == '__main__':
    create_admin_if_not_exists()
    app.run(host="0.0.0.0", port=5000, debug=False)
