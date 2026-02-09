from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime, timedelta
import os

app = Flask(__name__, static_folder='templates', static_url_path='')

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://localhost/sprints_db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'

# Fix for Railway PostgreSQL URL
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://', 1)

CORS(app, resources={r"/api/*": {"origins": "*"}})
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ==================== MODELS ====================

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    sprints = db.relationship('Sprint', backref='user', lazy=True, cascade='all, delete-orphan')
    tasks = db.relationship('Task', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    
    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)
    
    def to_dict(self):
        return {
            'id': self.id,
            'email': self.email,
            'name': self.name,
            'created_at': self.created_at.isoformat()
        }

class Sprint(db.Model):
    __tablename__ = 'sprints'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    start_date = db.Column(db.String(20), nullable=False)
    end_date = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    tasks = db.relationship('Task', backref='sprint', lazy=True, cascade='all, delete-orphan')
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'startDate': self.start_date,
            'endDate': self.end_date,
            'createdAt': self.created_at.isoformat(),
            'tasks': [task.to_dict() for task in self.tasks if not task.is_backlog]
        }

class Task(db.Model):
    __tablename__ = 'tasks'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(500), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    is_backlog = db.Column(db.Boolean, default=False)
    start_date = db.Column(db.String(20), nullable=True)
    end_date = db.Column(db.String(20), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    sprint_id = db.Column(db.Integer, db.ForeignKey('sprints.id'), nullable=True)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'category': self.category,
            'completed': self.completed,
            'isBacklog': self.is_backlog,
            'sprintId': self.sprint_id,
            'startDate': self.start_date,
            'endDate': self.end_date,
            'createdAt': self.created_at.isoformat()
        }

# ==================== SERVE FRONTEND ====================

@app.route('/')
def index():
    return send_from_directory('templates', 'index.html')

# ==================== AUTH ROUTES ====================

@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.json
        
        # Validation
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Check if user exists
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create user
        user = User(
            email=data['email'],
            name=data.get('name', '')
        )
        user.set_password(data['password'])
        
        db.session.add(user)
        db.session.commit()
        
        # Create access token
        access_token = create_access_token(identity=str(user.id))
        
        return jsonify({
            'token': access_token,
            'user': user.to_dict()
        }), 201
    except Exception as e:
        print(f"Registration error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.json
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'error': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if not user or not user.check_password(data['password']):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        access_token = create_access_token(identity=str(user.id))
        
        return jsonify({
            'token': access_token,
            'user': user.to_dict()
        }), 200
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Login failed'}), 500

@app.route('/api/auth/me', methods=['GET'])
@jwt_required()
def get_current_user():
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(user.to_dict()), 200
    except Exception as e:
        print(f"Get user error: {e}")
        return jsonify({'error': 'Authentication failed'}), 401

# ==================== SPRINT ROUTES ====================

@app.route('/api/sprints', methods=['GET'])
@jwt_required()
def get_sprints():
    try:
        user_id = int(get_jwt_identity())
        sprints = Sprint.query.filter_by(user_id=user_id).order_by(Sprint.created_at.desc()).all()
        return jsonify([sprint.to_dict() for sprint in sprints]), 200
    except Exception as e:
        print(f"Get sprints error: {e}")
        return jsonify({'error': 'Failed to fetch sprints'}), 500

@app.route('/api/sprints', methods=['POST'])
@jwt_required()
def create_sprint():
    try:
        user_id = int(get_jwt_identity())
        data = request.json
        
        sprint = Sprint(
            name=data['name'],
            start_date=data['startDate'],
            end_date=data['endDate'],
            user_id=user_id
        )
        
        db.session.add(sprint)
        db.session.commit()
        
        return jsonify(sprint.to_dict()), 201
    except Exception as e:
        print(f"Create sprint error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Failed to create sprint'}), 500

@app.route('/api/sprints/<int:sprint_id>', methods=['DELETE'])
@jwt_required()
def delete_sprint(sprint_id):
    try:
        user_id = int(get_jwt_identity())
        sprint = Sprint.query.filter_by(id=sprint_id, user_id=user_id).first()
        
        if not sprint:
            return jsonify({'error': 'Sprint not found'}), 404
        
        db.session.delete(sprint)
        db.session.commit()
        
        return '', 204
    except Exception as e:
        print(f"Delete sprint error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete sprint'}), 500

# ==================== TASK ROUTES ====================

@app.route('/api/backlog', methods=['GET'])
@jwt_required()
def get_backlog():
    try:
        user_id = int(get_jwt_identity())
        tasks = Task.query.filter_by(user_id=user_id, is_backlog=True).order_by(Task.created_at).all()
        return jsonify([task.to_dict() for task in tasks]), 200
    except Exception as e:
        print(f"Get backlog error: {e}")
        return jsonify({'error': 'Failed to fetch backlog'}), 500

@app.route('/api/tasks', methods=['POST'])
@jwt_required()
def create_task():
    try:
        user_id = int(get_jwt_identity())
        data = request.json
        
        task = Task(
            title=data['title'],
            description=data.get('description', ''),
            category=data['category'],
            is_backlog=data.get('isBacklog', False),
            sprint_id=data.get('sprintId'),
            start_date=data.get('startDate'),
            end_date=data.get('endDate'),
            user_id=user_id
        )
        
        db.session.add(task)
        db.session.commit()
        
        return jsonify(task.to_dict()), 201
    except Exception as e:
        print(f"Create task error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Failed to create task'}), 500

@app.route('/api/tasks/<int:task_id>', methods=['PATCH'])
@jwt_required()
def update_task(task_id):
    try:
        user_id = int(get_jwt_identity())
        task = Task.query.filter_by(id=task_id, user_id=user_id).first()
        
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        data = request.json
        
        if 'completed' in data:
            task.completed = data['completed']
        if 'title' in data:
            task.title = data['title']
        if 'description' in data:
            task.description = data['description']
        if 'category' in data:
            task.category = data['category']
        if 'startDate' in data:
            task.start_date = data['startDate']
        if 'endDate' in data:
            task.end_date = data['endDate']
        
        db.session.commit()
        
        return jsonify(task.to_dict()), 200
    except Exception as e:
        print(f"Update task error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Failed to update task'}), 500

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
@jwt_required()
def delete_task(task_id):
    try:
        user_id = int(get_jwt_identity())
        task = Task.query.filter_by(id=task_id, user_id=user_id).first()
        
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        db.session.delete(task)
        db.session.commit()
        
        return '', 204
    except Exception as e:
        print(f"Delete task error: {e}")
        db.session.rollback()
        return jsonify({'error': 'Failed to delete task'}), 500

# ==================== STATS ROUTES ====================

@app.route('/api/stats', methods=['GET'])
@jwt_required()
def get_stats():
    try:
        user_id = int(get_jwt_identity())
        
        total_sprints = Sprint.query.filter_by(user_id=user_id).count()
        total_tasks = Task.query.filter_by(user_id=user_id, is_backlog=False).count()
        completed_tasks = Task.query.filter_by(user_id=user_id, is_backlog=False, completed=True).count()
        backlog_tasks = Task.query.filter_by(user_id=user_id, is_backlog=True).count()
        
        return jsonify({
            'totalSprints': total_sprints,
            'totalTasks': total_tasks,
            'completedTasks': completed_tasks,
            'backlogTasks': backlog_tasks,
            'completionRate': round((completed_tasks / total_tasks * 100) if total_tasks > 0 else 0, 1)
        }), 200
    except Exception as e:
        print(f"Get stats error: {e}")
        return jsonify({'error': 'Failed to fetch stats'}), 500

# ==================== HEALTH CHECK ====================

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'database': 'connected'
    }), 200

# ==================== DATABASE INIT ====================

def init_db():
    with app.app_context():
        db.create_all()
        print("✅ Database tables created successfully!")

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
