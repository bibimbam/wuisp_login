from flask import Flask, request, render_template, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import jwt
import datetime

JWT_SECRET = 'hello' #서버 비밀키
JWT_ALGORITHM = 'HS256' #알고리즘
JWT_EXP_DELTA_SECONDS = 3600 #토큰 유효시간 1시간

app = Flask(__name__)
app.secret_key = 'hi'

#토큰 생성
def create_token(user_id):
    payload = {
        'user_id': user_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token

#토큰 검증
def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload['user_id']
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

# 데이터베이스 파일명
DATABASE = 'users.db'

def get_db():
    """데이터베이스 연결 객체를 가져오거나 새로 생성합니다."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # 딕셔너리 형태로 결과 반환
    return conn

def init_db():
    """데이터베이스 테이블을 초기화합니다."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        db.commit()

@app.route('/')
def home():
    """홈 페이지를 렌더링합니다."""
    return render_template('index.html')

# 로그인 페이지
@app.route('/login', methods=['GET', 'POST'])
def login():
    """사용자 로그인 처리 및 페이지를 렌더링합니다."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        user = cursor.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password'], password):
            token = create_token(user['id'])
            response = redirect(url_for('dashboard'))
            response.set_cookie('token', token)# 토큰(jwt)을 쿠키에 저장

            #session['user_id'] = user['id']
            flash('로그인에 성공했습니다!', 'success')
            return response
        else:
            flash('잘못된 사용자 이름 또는 비밀번호입니다.', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        cursor = db.cursor()
        
        # 사용자 이름 중복 확인
        existing_user = cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone()
        
        if existing_user:
            flash('이미 존재하는 ID입니다.', 'error')
            return render_template('register.html')
        
        # 비밀번호 해시 처리 후 저장
        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        db.commit()
        
        flash('등록 성공. 로그인하세요.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# 대시보드
@app.route('/dashboard')
def dashboard():
    token = request.cookies.get('token')
    user_id = verify_token(token)
    if not user_id:
        flash('먼저 로그인해야 합니다.', 'error')
        return redirect(url_for('login'))
    
    '''
    if 'user_id' not in session:
        flash('먼저 로그인해야 합니다.', 'error')
        return redirect(url_for('login'))
    '''
    
    return render_template('dashboard.html')

#로그아웃 페이지
@app.route('/logout')
def logout():
    flash('로그아웃되었습니다.', 'success')
    response = redirect(url_for('login'))
    response.delete_cookie('token')  # 쿠키에서 토큰 삭제
    # session.pop('user_id', None)
    # session.pop('_flashes', None)  # 모든 flash 메시지 초기화
    return response # 로그인 페이지로 이동


if __name__ == '__main__':
    # 서버 실행 전 데이터베이스 초기화
    init_db()
    app.run(debug=True)
