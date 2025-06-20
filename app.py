# app.py - Main Flask Application
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, DateField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length, Optional
from datetime import datetime, date
import os

# Initialize Flask app
app = Flask(__name__)

# Configuration - Essential for cloud deployment
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///assets.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Handle Heroku's postgres:// URL format
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('postgres://'):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace('postgres://', 'postgresql://')

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

@app.route('/debug/routes')
def list_routes():
    """Debug route to list all available routes"""
    import urllib.parse
    output = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        line = urllib.parse.unquote("{:50s} {:20s} {}".format(rule.endpoint, methods, rule))
        output.append(line)
    
    return '<pre>' + '\n'.join(sorted(output)) + '</pre>'

# ========================================
# DATABASE MODELS
# ========================================

class User(UserMixin, db.Model):
    """User model for authentication and role management"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='regular')  # 'admin' or 'regular'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to assignments
    assignments = db.relationship('Assignment', backref='assigned_user', lazy=True)
    
    def set_password(self, password):
        """Hash and set password"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check if provided password matches hash"""
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        """Check if user has admin role"""
        return self.role == 'admin'
    
    def __repr__(self):
        return f'<User {self.username}>'

class Asset(db.Model):
    """Asset model for IT equipment tracking"""
    __tablename__ = 'assets'
    
    id = db.Column(db.Integer, primary_key=True)
    asset_tag = db.Column(db.String(50), unique=True, nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)  # Laptop, Desktop, Monitor, etc.
    purchase_date = db.Column(db.Date, nullable=True)
    warranty_expiry = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='available')  # available, assigned, retired
    assigned_to = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    assignments = db.relationship('Assignment', backref='asset', lazy=True, cascade='all, delete-orphan')
    assigned_user = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_assets')
    
    def __repr__(self):
        return f'<Asset {self.asset_tag}: {self.name}>'

class Assignment(db.Model):
    """Assignment model for tracking asset history"""
    __tablename__ = 'assignments'
    
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('assets.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_date = db.Column(db.Date, nullable=False, default=date.today)
    returned_date = db.Column(db.Date, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Assignment Asset:{self.asset_id} User:{self.user_id}>'

# ========================================
# FLASK-LOGIN SETUP
# ========================================

@login_manager.user_loader
def load_user(user_id):
    """Load user for Flask-Login"""
    return User.query.get(int(user_id))

# ========================================
# FORMS (Using Flask-WTF for validation)
# ========================================

class LoginForm(FlaskForm):
    """Login form with validation"""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    """Registration form with validation"""
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = StringField('Email', validators=[DataRequired(), Length(min=5, max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    role = SelectField('Role', choices=[('regular', 'Regular User'), ('admin', 'Administrator')], 
                      validators=[DataRequired()])
    submit = SubmitField('Register')

class AssetForm(FlaskForm):
    """Asset form with validation"""
    asset_tag = StringField('Asset Tag', validators=[DataRequired(), Length(min=3, max=50)])
    name = StringField('Asset Name', validators=[DataRequired(), Length(min=3, max=100)])
    category = SelectField('Category', 
                          choices=[('Laptop', 'Laptop'), ('Desktop', 'Desktop'), 
                                 ('Monitor', 'Monitor'), ('Printer', 'Printer'),
                                 ('Phone', 'Phone'), ('Tablet', 'Tablet'), ('Other', 'Other')],
                          validators=[DataRequired()])
    purchase_date = DateField('Purchase Date', validators=[Optional()])
    warranty_expiry = DateField('Warranty Expiry', validators=[Optional()])
    status = SelectField('Status', 
                        choices=[('available', 'Available'), ('assigned', 'Assigned'), ('retired', 'Retired')],
                        validators=[DataRequired()])
    assigned_to = SelectField('Assigned To', coerce=int, validators=[Optional()])
    submit = SubmitField('Save Asset')

class AssignmentForm(FlaskForm):
    """Assignment form with validation"""
    asset_id = SelectField('Asset', coerce=int, validators=[DataRequired()])
    user_id = SelectField('User', coerce=int, validators=[DataRequired()])
    assigned_date = DateField('Assignment Date', validators=[DataRequired()], default=date.today)
    notes = TextAreaField('Notes', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Create Assignment')

# ========================================
# ROUTES
# ========================================

@app.route('/')
def index():
    """Home page with dashboard overview"""
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    # Get statistics for dashboard
    total_assets = Asset.query.count()
    available_assets = Asset.query.filter_by(status='available').count()
    assigned_assets = Asset.query.filter_by(status='assigned').count()
    total_users = User.query.count()
    
    # Recent assignments (last 5)
    recent_assignments = Assignment.query.order_by(Assignment.created_at.desc()).limit(5).all()
    
    return render_template('dashboard.html', 
                         total_assets=total_assets,
                         available_assets=available_assets, 
                         assigned_assets=assigned_assets,
                         total_users=total_users,
                         recent_assignments=recent_assignments)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash(f'Welcome back, {user.username}!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if username or email already exists
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('register.html', form=form)
        
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered. Please use a different email.', 'error')
            return render_template('register.html', form=form)
        
        # Create new user
        user = User(username=form.username.data, 
                   email=form.email.data,
                   role=form.role.data)
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    """User logout"""
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ========================================
# ASSET MANAGEMENT ROUTES
# ========================================

@app.route('/assets')
@login_required
def assets():
    """List all assets"""
    page = request.args.get('page', 1, type=int)
    assets = Asset.query.paginate(
        page=page, per_page=10, error_out=False
    )
    return render_template('assets.html', assets=assets, today=date.today())

@app.route('/assets/create', methods=['GET', 'POST'])
@login_required
def create_asset():
    """Create new asset (admin and regular users)"""
    form = AssetForm()
    
    # Populate assigned_to choices
    try:
        users = User.query.all()
        form.assigned_to.choices = [(0, 'None')] + [(u.id, u.username) for u in users]
    except Exception as e:
        print(f"Error populating user choices: {e}")
        form.assigned_to.choices = [(0, 'None')]
    
    if form.validate_on_submit():
        try:
            # Check if asset tag already exists
            if Asset.query.filter_by(asset_tag=form.asset_tag.data).first():
                flash('Asset tag already exists. Please use a unique tag.', 'error')
                return render_template('asset_form.html', form=form, title='Create Asset')
            
            asset = Asset(
                asset_tag=form.asset_tag.data,
                name=form.name.data,
                category=form.category.data,
                purchase_date=form.purchase_date.data,
                warranty_expiry=form.warranty_expiry.data,
                status=form.status.data,
                assigned_to=form.assigned_to.data if form.assigned_to.data != 0 else None
            )
            
            db.session.add(asset)
            db.session.commit()
            
            flash('Asset created successfully!', 'success')
            return redirect(url_for('assets'))
        except Exception as e:
            print(f"Error creating asset: {e}")
            flash('Error creating asset. Please try again.', 'error')
    
    return render_template('asset_form.html', form=form, title='Create Asset')

@app.route('/assets/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit_asset(id):
    """Edit asset (admin and regular users)"""
    asset = Asset.query.get_or_404(id)
    form = AssetForm(obj=asset)
    
    # Populate assigned_to choices
    users = User.query.all()
    form.assigned_to.choices = [(0, 'None')] + [(u.id, u.username) for u in users]
    
    if form.validate_on_submit():
        # Check if asset tag already exists (excluding current asset)
        existing_asset = Asset.query.filter_by(asset_tag=form.asset_tag.data).first()
        if existing_asset and existing_asset.id != asset.id:
            flash('Asset tag already exists. Please use a unique tag.', 'error')
            return render_template('asset_form.html', form=form, title='Edit Asset')
        
        asset.asset_tag = form.asset_tag.data
        asset.name = form.name.data
        asset.category = form.category.data
        asset.purchase_date = form.purchase_date.data
        asset.warranty_expiry = form.warranty_expiry.data
        asset.status = form.status.data
        asset.assigned_to = form.assigned_to.data if form.assigned_to.data != 0 else None
        
        db.session.commit()
        flash('Asset updated successfully!', 'success')
        return redirect(url_for('assets'))
    
    return render_template('asset_form.html', form=form, title='Edit Asset')

@app.route('/assets/<int:id>/delete', methods=['POST'])
@login_required
def delete_asset(id):
    """Delete asset (admin only)"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('assets'))
    
    asset = Asset.query.get_or_404(id)
    db.session.delete(asset)
    db.session.commit()
    
    flash('Asset deleted successfully!', 'success')
    return redirect(url_for('assets'))

# ========================================
# USER MANAGEMENT ROUTES
# ========================================

@app.route('/users')
@login_required
def users():
    """List all users"""
    page = request.args.get('page', 1, type=int)
    users = User.query.paginate(
        page=page, per_page=10, error_out=False
    )
    return render_template('users.html', users=users)

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
def create_user():
    """Create new user (admin only)"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('users'))
    
    form = RegisterForm()
    if form.validate_on_submit():
        # Check if username or email already exists
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists. Please choose a different one.', 'error')
            return render_template('user_form.html', form=form, title='Create User')
        
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered. Please use a different email.', 'error')
            return render_template('user_form.html', form=form, title='Create User')
        
        # Create new user
        user = User(username=form.username.data, 
                   email=form.email.data,
                   role=form.role.data)
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash(f'User {user.username} created successfully!', 'success')
        return redirect('/users')
    
    return render_template('user_form.html', form=form, title='Create User')

@app.route('/users/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def delete_user(id):
    """Delete user (admin only)"""
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('users'))
    
    if id == current_user.id:
        flash('You cannot delete your own account.', 'error')
        return redirect(url_for('users'))
    
    user = User.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    
    flash('User deleted successfully!', 'success')
    return redirect(url_for('users'))

# ========================================
# ASSIGNMENT ROUTES
# ========================================

@app.route('/assignments')
@login_required
def assignments():
    """List all assignments"""
    page = request.args.get('page', 1, type=int)
    assignments = Assignment.query.order_by(Assignment.created_at.desc()).paginate(
        page=page, per_page=10, error_out=False
    )
    return render_template('assignments.html', assignments=assignments)

@app.route('/assignments/<int:id>/return', methods=['POST'])
@login_required
def return_assignment(id):
    """Mark assignment as returned"""
    assignment = Assignment.query.get_or_404(id)
    
    # Update assignment
    assignment.returned_date = date.today()
    
    # Update asset status
    asset = assignment.asset
    asset.status = 'available'
    asset.assigned_to = None
    
    db.session.commit()
    
    flash(f'Asset {asset.asset_tag} has been returned successfully!', 'success')
    return redirect(url_for('assignments'))

@app.route('/assignments/create', methods=['GET', 'POST'])
@login_required
def create_assignment():
    """Create new assignment"""
    form = AssignmentForm()
    
    # Populate choices
    try:
        available_assets = Asset.query.filter_by(status='available').all()
        form.asset_id.choices = [(a.id, f"{a.asset_tag} - {a.name}") for a in available_assets]
        
        users = User.query.all()
        form.user_id.choices = [(u.id, u.username) for u in users]
    except Exception as e:
        print(f"Error populating form choices: {e}")
        form.asset_id.choices = []
        form.user_id.choices = []
        flash('Error loading form data. Please try again.', 'error')
    
    if form.validate_on_submit():
        try:
            assignment = Assignment(
                asset_id=form.asset_id.data,
                user_id=form.user_id.data,
                assigned_date=form.assigned_date.data,
                notes=form.notes.data
            )
            
            # Update asset status
            asset = Asset.query.get(form.asset_id.data)
            if asset:
                asset.status = 'assigned'
                asset.assigned_to = form.user_id.data
            
            db.session.add(assignment)
            db.session.commit()
            
            flash('Assignment created successfully!', 'success')
            return redirect(url_for('assignments'))
        except Exception as e:
            print(f"Error creating assignment: {e}")
            flash('Error creating assignment. Please try again.', 'error')
    
    return render_template('assignment_form.html', form=form, title='Create Assignment')

# ========================================
# ERROR HANDLERS
# ========================================

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# ========================================
# DATABASE INITIALIZATION
# ========================================

def create_sample_data():
    """Create sample data for testing"""
    
    # Create admin user
    admin = User(username='admin', email='admin@company.com', role='admin')
    admin.set_password('admin123')
    db.session.add(admin)
    
    # Create regular users
    users_data = [
        ('john_doe', 'john@company.com', 'regular'),
        ('jane_smith', 'jane@company.com', 'regular'),
        ('mike_jones', 'mike@company.com', 'regular'),
        ('sarah_wilson', 'sarah@company.com', 'regular'),
        ('david_brown', 'david@company.com', 'regular'),
        ('emma_davis', 'emma@company.com', 'regular'),
        ('chris_miller', 'chris@company.com', 'regular'),
        ('lisa_garcia', 'lisa@company.com', 'regular'),
        ('tom_anderson', 'tom@company.com', 'regular')
    ]
    
    for username, email, role in users_data:
        user = User(username=username, email=email, role=role)
        user.set_password('password123')
        db.session.add(user)
    
    db.session.commit()
    
    # Create sample assets
    assets_data = [
        ('LAP001', 'Dell Latitude 5520', 'Laptop', '2023-01-15', '2026-01-15', 'assigned'),
        ('LAP002', 'HP EliteBook 840', 'Laptop', '2023-02-20', '2026-02-20', 'available'),
        ('DSK001', 'Dell OptiPlex 7090', 'Desktop', '2023-03-10', '2026-03-10', 'assigned'),
        ('MON001', 'Dell U2720Q 27"', 'Monitor', '2023-01-15', '2026-01-15', 'assigned'),
        ('MON002', 'LG 24GL600F', 'Monitor', '2023-02-01', '2026-02-01', 'available'),
        ('PRN001', 'HP LaserJet Pro', 'Printer', '2022-12-01', '2025-12-01', 'available'),
        ('PHN001', 'iPhone 13 Pro', 'Phone', '2023-04-01', '2025-04-01', 'assigned'),
        ('TAB001', 'iPad Pro 11"', 'Tablet', '2023-05-15', '2025-05-15', 'available'),
        ('LAP003', 'MacBook Pro 16"', 'Laptop', '2023-06-01', '2026-06-01', 'assigned'),
        ('DSK002', 'iMac 24" M1', 'Desktop', '2023-07-01', '2026-07-01', 'available')
    ]
    
    users = User.query.all()
    
    for i, (tag, name, category, purchase, warranty, status) in enumerate(assets_data):
        asset = Asset(
            asset_tag=tag,
            name=name,
            category=category,
            purchase_date=datetime.strptime(purchase, '%Y-%m-%d').date(),
            warranty_expiry=datetime.strptime(warranty, '%Y-%m-%d').date(),
            status=status,
            assigned_to=users[i % len(users)].id if status == 'assigned' else None
        )
        db.session.add(asset)
    
    db.session.commit()
    
    # Create sample assignments
    assignments_data = [
        (1, 2, '2023-01-20', None, 'Initial laptop assignment'),
        (3, 3, '2023-03-15', None, 'Desktop for development work'),
        (4, 2, '2023-01-20', None, 'External monitor'),
        (7, 4, '2023-04-05', None, 'Company phone'),
        (9, 5, '2023-06-10', None, 'MacBook for design work'),
        (1, 6, '2023-02-01', '2023-06-01', 'Temporary assignment'),
        (2, 7, '2023-01-10', '2023-05-15', 'Project laptop'),
        (5, 8, '2023-03-01', '2023-08-01', 'Monitor for remote work'),
        (8, 9, '2023-05-20', '2023-09-20', 'iPad for presentations'),
        (6, 10, '2023-04-15', '2023-10-15', 'Printer setup')
    ]
    
    for asset_id, user_id, assigned, returned, notes in assignments_data:
        assignment = Assignment(
            asset_id=asset_id,
            user_id=user_id,
            assigned_date=datetime.strptime(assigned, '%Y-%m-%d').date(),
            returned_date=datetime.strptime(returned, '%Y-%m-%d').date() if returned else None,
            notes=notes
        )
        db.session.add(assignment)
    
    db.session.commit()
    print("Sample data created successfully!")

# ========================================
# APPLICATION STARTUP
# ========================================

if __name__ == '__main__':
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Create sample data if no users exist
        if User.query.count() == 0:
            create_sample_data()
    
    # Run the application
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)  # Enable debug mode to see errors