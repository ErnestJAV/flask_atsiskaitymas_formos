from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, EqualTo, ValidationError
from flask_login import current_user
import main
from wtforms_sqlalchemy.fields import QuerySelectField


class AddGroup(FlaskForm):
    name = StringField('Group', [DataRequired()])
    description = StringField('Description', [DataRequired()])
    submit = SubmitField('Submit')


class AddBill(FlaskForm):
    description = StringField('Description', [DataRequired()])
    amount = StringField('Amount', [DataRequired()])
    submit = SubmitField('Submit')
    # groups = QuerySelectField(query_factory=main.Groups.query.all, allow_blank=False, get_label='name', get_pk=lambda obj: str(obj))


class SignUpForm(FlaskForm):
    email_address = EmailField('Email Address', [DataRequired()])
    first_name = StringField('First Name', [DataRequired()])
    last_name = StringField('Last Name', [DataRequired()])
    password1 = PasswordField('Password', [DataRequired()])
    password2 = PasswordField('Password confirm', [DataRequired(), EqualTo('password1', 'Passwords must match')])
    submit = SubmitField('Sign Up')

    def validate_email_address(self, email_address):
        user = main.User.query.filter_by(email_address=self.email_address.data).first()
        if user:
            raise ValidationError('Email already exists. Sign in or use another email address.')


class SignInForm(FlaskForm):
    email_address = EmailField('Email Address', [DataRequired()])
    password = PasswordField('Password', [DataRequired()])
    submit = SubmitField('Sign In')


class UpdateAccountInformationForm(FlaskForm):
    email_address = EmailField('Email Address', [DataRequired()])
    first_name = StringField('First Name', [DataRequired()])
    last_name = StringField('Last Name', [DataRequired()])
    submit = SubmitField('Update Info')

    def validate_email_address(self, email_address):
        if current_user.email_address != self.email_address.data:
            user = main.User.query.filter_by(email_address=self.email_address.data).first()
            if user:
                raise ValidationError('Email already exists. Sign in or use another email address.')


class AddUserGroup(FlaskForm):
    groups = QuerySelectField(allow_blank=False, get_label='name',
                              get_pk=lambda obj: str(obj))
    email_address = EmailField('Email Address', [DataRequired()])
    submit = SubmitField('Add user')