from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# Set up the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quiz.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Initialize the database
db = SQLAlchemy(app)


class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(200), nullable=False)
    choice1 = db.Column(db.String(100), nullable=False)
    choice2 = db.Column(db.String(100), nullable=False)
    choice3 = db.Column(db.String(100), nullable=False)
    choice4 = db.Column(db.String(100), nullable=False)
    answer = db.Column(db.String(100), nullable=False)


# Create the database tables
with app.app_context():
    db.create_all()


@app.route("/submit_quiz", methods=['GET'])
def submit_quiz():
    return render_template("form.html")


@app.route("/view_quiz", methods=['GET'])
def view_quiz():
    quizzes = Quiz.query.all()
    return render_template("view_quiz.html", quizzes=quizzes)


@app.route("/save_quiz", methods=['POST'])
def save_quiz():
    # Retrieve form data
    question = request.form['question']
    choice1 = request.form['option1']
    choice2 = request.form['option2']
    choice3 = request.form['option3']
    choice4 = request.form['option4']
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

    return redirect("/view_quiz")


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/layout')
def layout():
    return render_template('layout.html')

@app.route('/hello')
def hello_world():
    return render_template('hello')

@app.route('/take_quiz', methods=['GET'])
def take_quiz():
    quizzes = Quiz.query.all()  # Retrieve all quiz questions
    return render_template('take_quiz.html', quizzes=quizzes)


@app.route('/submit_exam', methods=['POST'])
def submit_exam():
    quizzes = Quiz.query.all()  # Retrieve all quiz questions
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

    return render_template('result.html', result=result)


if __name__ == '__main__':
    app.run(debug=True)
