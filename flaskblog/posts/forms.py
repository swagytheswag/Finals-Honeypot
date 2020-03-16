from flask_wtf import  FlaskForm
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired


class PostForm(FlaskForm):
    title = StringField('Platform', validators=[DataRequired()])
    content = TextAreaField('Password', validators=[DataRequired()])
    submit = SubmitField('Save Password')