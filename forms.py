from flask_wtf import FlaskForm
from wtforms import EmailField, PasswordField, TextAreaField, PasswordField, SubmitField, StringField
from wtforms.validators import DataRequired, Email, EqualTo, Length, Email, Optional
from wtforms import FloatField, IntegerField,  SelectField, DateField, DecimalField, FileField
from flask_wtf.file import FileAllowed


class SignUpForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    # phone_number = StringField('Phone', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Register')

    
class LoginForm(FlaskForm):
    username = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField('log in')



class EditUserForm(FlaskForm):
    name= StringField('Username', validators=[DataRequired()])
    username = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Update')




class UploadNewspaperForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    pdf_file = FileField('PDF File', validators=[DataRequired(), FileAllowed(['pdf'], 'PDFs only!')])
    publication_date = DateField('Publication Date', format='%Y-%m-%d', validators=[DataRequired()])
    submit = SubmitField('Upload')