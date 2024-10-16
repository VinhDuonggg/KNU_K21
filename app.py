import pytz
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from functools import wraps
from werkzeug.utils import secure_filename
import csv
import os

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Set up the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SQLALCHEMY_BINDS'] = {
    'user': 'sqlite:///database.db'
}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)  # Initialize Flask-Migrate
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __bind_key__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Add this line

    # Add cascade to delete user's scores when user is deleted
    quiz_scores = db.relationship('QuizScore', backref='user', lazy=True, cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class QuizScore(db.Model):
    __bind_key__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"), nullable=False)
    #user = db.relationship('User', backref=db.backref('quiz_scores', lazy=True))
    score = db.Column(db.Integer, nullable=False)
    date_taken = db.Column(db.DateTime, default=lambda: datetime.utcnow().replace(tzinfo=pytz.UTC))

    def __repr__(self):
        return f'<QuizScore user_id={self.user_id} score={self.score} date_taken={self.date_taken}>'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('You do not have permission to access this page.')
            return redirect(url_for('layout'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('layout'))
        else:
            return render_template('login.html', error='Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        admin_key = request.form.get('admin_key')  # Additional field for admin registration

        user = User.query.filter_by(username=username).first()
        if user:
            return render_template('register.html', error='Username already exists.')
        else:
            new_user = User(username=username)
            new_user.set_password(password)

            # Set user as admin if admin_key matches (for example, "admin_secret_key")
            if admin_key == "your_admin_secret_key":
                new_user.is_admin = True

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('layout'))
    return render_template('register.html')

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('Your account has been deleted successfully.')
        if current_user.id == user_id:
            logout_user()  # Log out the user after deleting their account
        return redirect(url_for('login'))
    else:
        flash('User not found.')
        return redirect(url_for('layout'))


class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    choice1 = db.Column(db.String(100), nullable=False)
    choice2 = db.Column(db.String(100), nullable=False)
    choice3 = db.Column(db.String(100), nullable=False)
    choice4 = db.Column(db.String(100), nullable=False)
    answer = db.Column(db.String(100), nullable=False)

@app.route('/submit_quiz', methods=['GET'])
@login_required
@admin_required
def submit_quiz():
    return render_template('form.html')

@app.route('/view_quiz', methods=['GET'])
@login_required
@admin_required
def view_quiz():
    quizzes = Quiz.query.all()
    return render_template('view_quiz.html', quizzes=quizzes)

@app.route('/save_quiz', methods=['POST'])
@login_required
@admin_required
def save_quiz():
    if not current_user.is_admin:
        flash('You do not have permission to add a quiz.')
        return redirect(url_for('view_quiz'))

    question = request.form['question']
    choice1 = request.form['option1']
    choice2 = request.form['option2']
    choice3 = request.form['option3']
    choice4 = request.form['option4']
    answer = request.form['correct']
    new_quiz = Quiz(
        question=question,
        choice1=choice1,
        choice2=choice2,
        choice3=choice3,
        choice4=choice4,
        answer=answer
    )

    db.session.add(new_quiz)
    db.session.commit()

    return redirect('/view_quiz')

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/layout')
@login_required
def layout():
    return render_template('layout.html')

@app.route('/take_quiz', methods=['GET'])
@login_required
def take_quiz():
    quizzes = Quiz.query.all()
    return render_template('take_quiz.html', quizzes=quizzes)

from datetime import datetime

@app.route('/submit_exam', methods=['POST'])
@login_required
def submit_exam():
    quizzes = Quiz.query.all()
    score = 0

    for quiz in quizzes:
        selected_answer = request.form.get(f'question_{quiz.id}')
        if selected_answer == quiz.answer:
            score += 1

    total_questions = len(quizzes)
    result = {
        "score": score,
        "total_questions": total_questions
    }

    # Save the score to the database
    quiz_score = QuizScore(user_id=current_user.id, score=score)
    db.session.add(quiz_score)
    db.session.commit()

    return render_template('result.html', result=result)


@app.route('/view_scores', methods=['GET'])
@login_required
def view_scores():
    scores = QuizScore.query.filter_by(user_id=current_user.id).all()
    for score in scores:
        score.date_taken = score.date_taken.astimezone()

    return render_template('view_scores.html', scores=scores)


@app.route('/delete_quiz/<int:quiz_id>', methods=['POST'])
@login_required
@admin_required
def delete_quiz(quiz_id):
    quiz = Quiz.query.get(quiz_id)
    if quiz:
        db.session.delete(quiz)
        db.session.commit()
        flash('Quiz has been deleted successfully.')
    else:
        flash('Quiz not found.')
    return redirect(url_for('view_quiz'))

@app.route('/manage_students', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_students():
    users = User.query.all()

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')

        user = User.query.get(user_id)
        if not user:
            flash("User not found.")
            return redirect(url_for('manage_students'))

        if action == 'delete':
            # Delete the user
            db.session.delete(user)
            db.session.commit()
            flash(f'User {user.username} has been deleted successfully.')
        elif action == 'change_password':
            new_password = request.form.get('new_password')
            if new_password:
                user.set_password(new_password)
                db.session.commit()
                flash(f'Password for {user.username} has been updated.')
            else:
                flash("New password cannot be empty.")

    return render_template('manage_students.html', users=users)

@app.route('/admin_delete_user/<int:user_id>', methods=['POST'])
@login_required
def admin_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully.')
    return redirect(url_for('manage_students'))

@app.route('/change_password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def change_password(user_id):
    user = User.query.get(user_id)
    if not user:
        flash("User not found.")
        return redirect(url_for('manage_students'))

    new_password = request.form.get('new_password')
    if new_password:
        user.set_password(new_password)
        db.session.commit()
        flash(f"Password for {user.username} has been updated.")
    else:
        flash("New password cannot be empty.")
    return redirect(url_for('manage_students'))


@app.route('/upload_questions', methods=['GET', 'POST'])
@login_required
@admin_required
def upload_questions():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join('uploads', filename)
            file.save(file_path)

            # Parse the file and save questions
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if len(row) == 6:
                            question, choice1, choice2, choice3, choice4, answer = row
                            new_quiz = Quiz(
                                question=question,
                                choice1=choice1,
                                choice2=choice2,
                                choice3=choice3,
                                choice4=choice4,
                                answer=answer
                            )
                            db.session.add(new_quiz)
                    db.session.commit()
                flash('Questions uploaded successfully!')
            except UnicodeDecodeError as e:
                flash(f"Error reading the file: {e}")
            return redirect(url_for('view_quiz'))
    return render_template('upload_file.html')

@app.route('/modify_question/<int:question_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def modify_question(question_id):
    # Fetch the question by its ID
    question = Quiz.query.get_or_404(question_id)

    if request.method == 'POST':
        # Get form data from the user to modify the question
        question_text = request.form.get('question')
        choice1 = request.form.get('choice1')
        choice2 = request.form.get('choice2')
        choice3 = request.form.get('choice3')
        choice4 = request.form.get('choice4')
        answer = request.form.get('answer')
        pass

        # Validate input (you can add more validation here if needed)
        if not question_text or not choice1 or not choice2 or not choice3 or not choice4 or not answer:
            flash('All fields are required!')
            return redirect(url_for('modify_question', question_id=question_id))

        if answer not in [choice1, choice2, choice3, choice4]:
            flash('The answer must be one of the choices!')
            return redirect(url_for('modify_question', question_id=question_id))

        # Update the question's details
        question.question = question_text
        question.choice1 = choice1
        question.choice2 = choice2
        question.choice3 = choice3
        question.choice4 = choice4
        question.answer = answer

        # Commit changes to the database
        try:
            db.session.commit()
            flash('Question updated successfully!')
            return redirect(url_for('view_quiz'))  # Redirect to the quiz list or view page
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating question: {e}')
            return redirect(url_for('modify_question', question_id=question_id))

    # If GET request, render the form pre-populated with the existing question data
    return render_template('modify_question.html', question=question)


if __name__ == '__main__':
    with app.app_context():
        # Add this line before db.create_all()
        #db.drop_all()
        db.create_all()
    app.run(debug=True)
