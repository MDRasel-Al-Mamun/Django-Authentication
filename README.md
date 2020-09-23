# Django Authentication Project

To Create a Authentication System for Django Website

> - <a href="#validition">1. Sign Up Form Validition </a>

> - <a href="#signup">2. Create an account with email verification </a>

> - <a href="#signin">3. Sign In & Sign Out Precess  </a>

> - <a href="#reset">4. Reset Password & Set New Password </a>

## 1. Sign Up Form Validition <a href="" name="validition"> - </a>

- <a href="#jquery"> jQuery Form Validition </a>
- <a href="#password"> Password strength check with jQuery </a>
- <a href="#username">Username Validition with JsonResponse </a>
- <a href="#email">Email Validition with JsonResponse </a>


### jQuery Form Validition <a href="" name="jquery"> - </a>

* static > js > add javascript   

  - > jquery-3.5.1.min.js
  - > jquery.validate.min.js

* templates > base > scripts.html   

```django
<script type="text/javascript" src="{% static 'js/jquery-3.5.1.min.js' %}"></script>

<script type="text/javascript" src="{% static 'js/jquery.validate.min.js' %}"></script>
```

* templates > authentication > signup.html   

```html
<form class="border border-light p-5" id="validation-form" method="POST">
  <p class="h4 mb-4 text-center ">Sign up</p>

  <div class="row mt-4">
    <!-- First name -->
    <div class="col">
      <input type="text" name="first_name" class="form-control" placeholder="First name *" />
    </div>
    <!-- Last name -->
    <div class="col">
      <input type="text" name="last_name" class="form-control" placeholder="Last name *" />
    </div>
  </div>

  <!-- Username -->
  <div class="col">
    <input type="text" id="usernameField" name="username" class="form-control mt-4" placeholder="Username *" />
  </div>

  <!-- E-mail -->
  <div class="col">
    <input type="email" id="emailField" name="email" class="form-control mt-4" placeholder="E-mail *">
  </div>

  <!-- Password -->
  <div class="col">
    <input type="password" id="passwordField" name="password" class="form-control mt-4" placeholder="Password *">
  </div>

  <!-- Confirm Password -->
  <div class="col">
    <input type="password" name="confirm_password" class="form-control mt-4"
      placeholder="Confirm Password *">
  </div>

  <!-- Policy -->
  <div class="pt-4">
    <input type="checkbox" name="agree" id="policy">
    <label for="policy">
      Please agree to our policy
    </label>
  </div>

  <!-- Sign up button -->
  <button class="btn btn-info my-4 btn-block" name="signup" type="submit">
    Sign Up
  </button>

  <!-- Social Sign Up -->
  <p class="text-center">or sign up with:</p>

  <div class="text-center">
    <a href="" class="text-primary mx-2">
      <i class="fab fa-facebook-square fa-2x"></i>
    </a>
    <a href="#" class="text-secondary mx-2" role="button">
      <i class="fab fa-linkedin fa-2x"></i>
    </a>
    <a href="#" class="text-info mx-2">
      <i class="fab fa-twitter-square fa-2x"></i>
    </a>
    <a href="#" class="text-dark mx-2" role="button">
      <i class="fab fa-github-square fa-2x"></i>
    </a>
  </div>

  <hr>

  <!-- Terms of service -->
  <p class="text-center">By clicking <em>Sign up</em> you agree to our
    <a href="" target="_blank">terms of service</a>
  </p>
</form>
```

* static > js > main.js 

```javascript
$(document).ready(function () {
  $('#validation-form').validate({
    rules: {
      first_name: 'required',
      last_name: 'required',
      username: {
        required: true,
        minlength: 8,
      },
      email: {
        required: true,
        email: true,
      },
      password: {
        required: true,
        minlength: 8,
      },
      confirm_password: {
        required: true,
        equalTo: '#passwordField',
      },
    },
    messages: {
      firstname: 'Please enter your first name',
      lastname: 'Please enter your last name',
      username: {
        required: 'Please enter a username',
        minlength: 'Your username must consist of at least 8 characters',
      },
      email: 'Please enter a valid email address',
      password: {
        required: 'Please provide a password',
        minlength: 'Your password must be at least 8 characters long',
      },
      confirm_password: {
        required: 'Confirm your password',
        equalTo: 'Password not match',
      },
    },
    errorElement: 'em',
    errorPlacement: function (error, element) {
      // Add the `invalid-feedback` class to the error element
      error.addClass('invalid-feedback');

      if (element.prop('type') === 'checkbox') {
        error.insertAfter(element.next('label'));
      } else {
        error.insertAfter(element);
      }
    },
    highlight: function (element, errorClass, validClass) {
      $(element).addClass('is-invalid').removeClass('is-valid');
    },
    unhighlight: function (element, errorClass, validClass) {
      $(element).addClass('is-valid').removeClass('is-invalid');
    },
  });
});
```

* authentication > views.py   

```python
from django.shortcuts import render
from django.views.generic import View

class SignUpView(View):
    def get(self, request):
        return render(request, 'authentication/signup.html')
```

* authentication > urls.py   

```python
from django.urls import path
from .views import *

urlpatterns = [
    path('sign_up/', SignUpView.as_view(), name="signup"),
]
```

### Password strength check with jQuery <a href="" name="password"> - </a>

* static > js > add javascript   

  > jquery.passwordstrength.js

* templates > base > jscripts.html   

```django
<script type="text/javascript" src="{% static 'js/jquery.passwordstrength.js' %}"></script>
```

* templates > authentication > signup.html   

```html
<!-- Password -->
<input type="password" id="passwordField" name="password" class="form-control mt-4" placeholder="Password" />
```

* static > js > main.js 

```javascript
$(document).ready(function () {
    if ($.fn.passwordStrength) {
    $('#passwordField').passwordStrength({
      minimumChars: 8,
    });
  }
});
```

* static > css > style.css   

```css
#validation-form .progress {
  width: 100%;
  height: 5px;
  margin-top: 1rem;
  border-radius: 0;
  margin-bottom: 0.25rem;
}
#validation-form .password-score {
  font-size: 14px;
  font-weight: 700;
}
#validation-form .password-score span {
  font-size: 18px;
}
#validation-form .password-recommendation {
  font-size: 13px;
}
#validation-form .password-recommendation ul,
#validation-form .password-recommendation ol {
  padding-left: 0;
  list-style: none;
  text-decoration: none;
}
#validation-form #password-recommendation-heading {
  font-weight: 500;
  color: #0b0757;
  font-size: 14px;
  margin-bottom: 0.25rem;
}

```


### Username Validition with JsonResponse <a href="" name="username"> - </a>

* authentication > views.py   

```python
import json
from django.http import JsonResponse
from django.contrib.auth.models import User

class UsernameValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        username = data['username']
        if not str(username).isalnum():
            return JsonResponse({'username_error': 'Username should only contain alphanumeric characters'}, status=400)
        if User.objects.filter(username=username).exists():
            return JsonResponse({'username_error': 'Sorry username is already taken, choose another one'}, status=409)
        return JsonResponse({'username_valid': True})
```

* authentication > urls.py   

```python
from django.views.decorators.csrf import csrf_exempt
urlpatterns = [
    path('validate_username', csrf_exempt(UsernameValidationView.as_view()), name="validate_username"),
]
```

* templates > authentication >  signup.html   

```html
<!-- Username -->
<input
  type="text" id="usernameField" name="username" class="form-control mt-4" placeholder="Username *" />

<div class="usernameFeedBackArea invalid-feedback" style="display:none"></div>
```

* static > js > main.js   

```javascript
const usernameField = document.querySelector('#usernameField');
const feedBackArea = document.querySelector('.usernameFeedBackArea');

usernameField.addEventListener('keyup', (e) => {
  const usernameVal = e.target.value;
  usernameField.classList.remove('is-invalid');
  feedBackArea.style.display = 'none';
  if (usernameVal.length > 0) {
    fetch('/authentication/validate_username', {
      body: JSON.stringify({ username: usernameVal }),
      method: 'POST',
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.username_error) {
          usernameField.classList.add('is-invalid');
          feedBackArea.style.display = 'block';
          feedBackArea.innerHTML = `<p style="color:red";>${data.username_error}</p>`;
        }
      });
  }
});
```

### Email Validition with JsonResponse <a href="" name="email"> - </a>

* Command Prompt   

> ``` pip install validate-email ```

* authentication > views.py   

```python
from validate_email import validate_email

class EmailValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        email = data['email']
        if not validate_email(email):
            return JsonResponse({'email_error': 'Please provide a valid email'}, status=400)
        if User.objects.filter(email=email).exists():
            return JsonResponse({'email_error': 'Sorry, email is already used, choose another one '}, status=409)
        return JsonResponse({'email_valid': True})
```

* authentication > urls.py   

```python
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    path('validate_email', csrf_exempt(EmailValidationView.as_view()), name='validate_email'),
]
```

* templates > authentication >  signup.html   

```html
<!-- E-mail -->
<input
  type="email" id="emailField" name="email" class="form-control mt-4" placeholder="E-mail *" />

<div class="emailFeedBackArea invalid-feedback" style="display:none"></div>
```

* static > js > main.js   

```javascript
const emailField = document.querySelector('#emailField');
const emailFeedBackArea = document.querySelector('.emailFeedBackArea');

emailField.addEventListener('keyup', (e) => {
  const emailVal = e.target.value;
  emailField.classList.remove('is-invalid');
  emailFeedBackArea.style.display = 'none';
  if (emailVal.length > 0) {
    fetch('/authentication/validate_email', {
      body: JSON.stringify({ email: emailVal }),
      method: 'POST',
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.email_error) {
          emailField.classList.add('is-invalid');
          emailFeedBackArea.style.display = 'block';
          emailFeedBackArea.innerHTML = `<p style="color:red";>${data.email_error}</p>`;
        }
      });
  }
});
```

# 2. Create an account with email verification <a href="" name="signup"> - </a>

* templates > Create files 

- > authentication
  -  > email.html
  -  > signin.html

- > partials
  - >  _messages.html

* authProject > settings.py 

```python
from django.contrib import messages
from decouple import config

MESSAGE_TAGS = {
    messages.ERROR: 'danger'
}

EMAIL_BACKEND = config('EMAIL_BACKEND')
EMAIL_HOST = config('EMAIL_HOST')
EMAIL_HOST_USER = config('EMAIL_HOST_USER')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
EMAIL_USE_TLS = config('EMAIL_USE_TLS')
EMAIL_PORT = config('EMAIL_PORT', cast=int)
```

* root > Create a file > .env 

```
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=smtp.gmail.com
EMAIL_HOST_USER=abc@example.com
DEFAULT_FROM_EMAIL=abc@example.com
EMAIL_HOST_PASSWORD=*************
EMAIL_USE_TLS=True
EMAIL_PORT=587
```

* authentication > views.py 

```python
import threading
from django.contrib import messages
from django.core.mail import EmailMessage
from . utils import account_activation_token
from django.shortcuts import render, redirect
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError

# Speed Up Email Send
class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)
    def run(self):
        self.email.send(fail_silently=False)

class SignUpView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('home')
        else:
            return render(request, 'authentication/signup.html')

    # Collect Form Data

    def post(self, request):
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']

        context = {
            'message': first_name,
            'values': request.POST
        }

        if not User.objects.filter(username=username).exists():
            if not User.objects.filter(email=email).exists():
                if len(password) < 8:
                    return render(request, 'authentication/signup.html', context)
                user = User.objects.create_user(username=username, email=email)
                user.set_password(password)
                user.first_name = first_name
                user.last_name = last_name
                user.is_active = False
                user.save()

                # Send Confiramation Message

                current_site = get_current_site(request)
                email_subject = 'Activate your account'
                email_body = render_to_string('authentication/email.html', {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': account_activation_token.make_token(user),
                })

                email = EmailMessage(
                    email_subject,
                    email_body,
                    'noreply@semycolon.com',
                    [email],
                )
                EmailThread(email).start()
                return render(request, 'authentication/signup.html', context)
        return render(request, 'authentication/signup.html', context)


# Send Code Validation

class VerificationView(View):
    def get(self, request, uidb64, token):
        try:
            id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=id)

            if not account_activation_token.check_token(user, token):
                return redirect('signin'+'?message='+'User Already Activated')

            if user.is_active:
                return redirect('signin')
            user.is_active = True
            user.save()

            messages.success(request, 'Account Activated Successfully')
            return redirect('signin')

        except Exception as ex:
            pass

        return redirect('signin')

class SigninView(View):
    def get(self, request):
        return render(request, 'authentication/signin.html')
```

* authentication > urls.py 

```python
urlpatterns = [
    path('sign_in/', SigninView.as_view(), name="signin"),
    path('activate/<uidb64>/<token>', VerificationView.as_view(), name='activate'),
]
```

* authentication > Create file > (utils.py) 

```python
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from six import text_type
class AppTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (text_type(user.is_active) + text_type(user.pk) + text_type(timestamp))
account_activation_token = AppTokenGenerator()
```

* template > authentication > signup.html 

```django
<div class="container">
  <div class="row">
    <div class="col-md-7 mx-auto">
      
      {% if message %}
        <div class="text-center mt-5 pt-5">
          <h1>
            <span>Congratulations! {{ message }}</span>
          </h1>
          <h3 class="pt-3">
            Your Account Successfully Created
          </h3>
          <div class="py-2"></div>
          <h6>
            To Active Your Account, A Confirmation Code has Send to Your Email Address
          </h6>
          <h3 class="py-2">Please Go to Your Email</h3>
          <a href="https://mail.google.com/" target="_blank" class="btn btn-info p-3">
            Email Confiramation
          </a>
        </div>
      {% else %}
        
      <form class="border border-light p-5" id="validation-form" action="{% url 'signup' %}" method="POST">

        <p class="h4 mb-4 text-center ">Sign up</p>

        {% csrf_token %}
        {% include 'partials/_messages.html' %}

        <div class="row mt-4">
          <div class="col">
            <!-- First name -->
            <input type="text" id="first_name" name="first_name" class="form-control" placeholder="First name *" value="{{ values.first_name }}">
          </div>
          <div class="col">
            <!-- Last name -->
            <input type="text" id="last_name" name="last_name" class="form-control" placeholder="Last name *" value="{{ values.last_name }}">
          </div>
        </div>

        <!-- Username -->
        <div class="col">
          <input type="text" id="usernameField" name="username" class="form-control mt-4" placeholder="Username *" value="{{ values.username }}">

          <div class="usernameFeedBackArea invalid-feedback" style="display:none"></div>
        </div>

        <!-- E-mail -->
        <div class="col">
          <input type="email" id="emailField" name="email" class="form-control mt-4" placeholder="E-mail *" value="{{ values.email }}">

          <div class="emailFeedBackArea invalid-feedback" style="display:none"></div>
        </div>

        <!-- Password -->
        <div class="col">
          <input type="password" id="passwordField" name="password" class="form-control mt-4" placeholder="Password *">
        </div>

        <!-- Confirm Password -->
        <div class="col">
          <input type="password" id="" name="confirm_password" class="form-control mt-4"
            placeholder="Confirm Password *">
        </div>

        <!-- Policy -->
        <div class="pt-4">
          <input type="checkbox" name="agree" id="policy">
          <label for="policy">
            Please agree to our policy
          </label>
        </div>
        <!-- Sign up button -->
        <button class="btn btn-info my-4 btn-block" name="signup" type="submit">
          Sign Up
        </button>

        <!-- Sign In -->
        <p class="text-center">Already have an account?
          <a href="{% url 'signin' %}">Sign In</a>
        </p>

        <!-- Social Sign In -->
        <p class="text-center">or sign up with:</p>

        <div class="text-center">
          <a href="" class="text-primary mx-2">
            <i class="fab fa-facebook-square fa-2x"></i>
          </a>
          <a href="#" class="text-secondary mx-2" role="button">
            <i class="fab fa-linkedin fa-2x"></i>
          </a>
          <a href="#" class="text-info mx-2">
            <i class="fab fa-twitter-square fa-2x"></i>
          </a>
          <a href="#" class="text-dark mx-2" role="button">
            <i class="fab fa-github-square fa-2x"></i>
          </a>
        </div>

        <hr>

        <!-- Terms of service -->
        <p class="text-center">By clicking <em>Sign up</em> you agree to our
          <a href="" target="_blank">terms of service</a>
        </p>
      </form>

      {% endif %}
    </div>
  </div>
</div>
```

* template > authentication > email.html 

```django
{% autoescape off%}
Hi {{user.username}},
Thanks to join with us.
Please click this link below to verify your account
http://{{domain}}{% url 'activate' uidb64=uid token=token %}
{% endautoescape %}
```

* template > partials > _messages.html 

```django
{% if messages %}
<div class="messages">
  {% for message in messages %}
  <div {% if message.tags %} class="alert alert-sm alert-{{ message.tags }}" {% endif %}>
    {{ message }}
  </div>
  {% endfor %}
</div>
{% endif %}
```

* template > authentication > signin.html 

``` Create a sign in form ```


# 3. Sign In & Sign Out Precess <a href="" name="signin"> - </a>

* templates > authentication > signin.html

```html
<form class="border border-light p-5" id="validation-form" action="{% url 'signin' %}" method="POST">

  <p class="h4 mb-4 text-center ">Sign In</p>

  {% csrf_token %}
  {% include 'partials/_messages.html' %}

  <!-- Username -->
  <div class="col">
    <input type="text" id="usernameField" name="username" class="form-control mt-4" placeholder="Username *" value="{{ values.username }}">
  </div>

  <!-- Password -->
  <div class="col">
    <input type="password" id="password" name="password" class="form-control mt-4" placeholder="Password *">
  </div>

  <!-- Remember -->
  <div class="py-3">
    <input type="checkbox" name="agree" id="remember">
    <label for="remember">
      Remember me
    </label>
  </div>

  <!-- Forgot password -->
  <a href="" class="text-decoration-none">Forgot password?</a>

  <!-- Sign In button -->
  <button class="btn btn-info my-4 btn-block" name="signin" type="submit">
    Sign In
  </button>

  <!-- Sign Up -->
  <p class="text-center">Not a member?
    <a href="{% url 'signup' %}">Sign Up</a>
  </p>

  <!-- Social Sign In -->
  <p class="text-center">or sign in with:</p>

  <div class="text-center">
    <a href="" class="text-primary mx-2">
      <i class="fab fa-facebook-square fa-2x"></i>
    </a>
    <a href="#" class="text-secondary mx-2" role="button">
      <i class="fab fa-linkedin fa-2x"></i>
    </a>
    <a href="#" class="text-info mx-2">
      <i class="fab fa-twitter-square fa-2x"></i>
    </a>
    <a href="#" class="text-dark mx-2" role="button">
      <i class="fab fa-github-square fa-2x"></i>
    </a>
  </div>
</form>
```

* authentication > views.py

```python
from django.contrib import auth
from django.contrib.auth import logout

class SigninView(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('home')
        else:
            return render(request, 'authentication/signin.html')

    def post(self, request):

        context = {
            'values': request.POST
        }

        username = request.POST['username']
        password = request.POST['password']

        if username and password:
            user = auth.authenticate(username=username, password=password)

            if user:
                if user.is_active:
                    auth.login(request, user)
                    return redirect('home')
                messages.error(
                    request, 'Account is not active, please check your email')
                return render(request, 'authentication/signin.html', context)
            messages.error(request, 'Invalid credentials, try again')
            return render(request, 'authentication/signin.html', context)

        return render(request, 'authentication/signin.html', context)


def signoutView(request):
    logout(request)
    messages.success(request, 'You are sign out successfully')
    return redirect('signin')
```

* authentication > urls.py

```python
urlpatterns = [
    path('sign_in/', SigninView.as_view(), name="signin"),
    path('sign_out/', signoutView, name="signout"),
]
```

*templates > partials > _header.html

```django
{% if user.is_authenticated %}
  <a href="{% url 'signout' %}" class="nav-item nav-link"> Sign Out </a>
{% else %}
  <a href="{% url 'signin' %}" class="nav-item nav-link">Sign In</a>
{% endif %}
```

# 4. Reset Password & Set New Password <a href="" name="reset"> - </a>

* templates > Create files 

- > authentication
  -  > reset_password.html
  -  > new_password.html


* templates > authentication > reset_password.html

```html
<div class="container">
  <div class="row">
    <div class="col-md-7 mx-auto">

      {% if email %}
      <div class="text-center mt-5 pt-5">
        <h1>
          <span>Hi ! there,</span>
        </h1>
        <h3 class="pt-3">
          Password Reset Successfully
        </h3>
        <div class="py-2"></div>
        <h6>
          To Confirm Your Raset Password, A Confirmation Code has Send to this
        </h6>
        <h5>{{ email }}</h5>
        <h3 class="py-2">Please Go to Your Email</h3>
        <a href="https://mail.google.com/" target="_blank" class="btn btn-info p-3">
          Email Confiramation
        </a>
      </div>
      {% else %}

      <form class="border border-light p-5" id="validation-form" action="{% url 'reset_password' %}" method="POST">

        <p class="h4 mb-4 text-center ">Reset Password</p>

        {% csrf_token %}

        {% include 'partials/_messages.html' %}

        <!-- E-mail -->
        <div class="col">
          <input type="email" id="email" name="email" class="form-control mt-4" placeholder="E-mail *" value="{{ values.email }}">
        </div>

        <!-- Reset Password button -->
        <button class="btn btn-info my-4 btn-block" name="reset_password" type="submit">
          Reset Password
        </button>

         <!-- Sign Up -->
         <p class="text-center">Not a member?
           <a href="{% url 'signup' %}">Sign Up</a>
         </p>
   
      </form>

      {% endif %}
    </div>
  </div>
</div>

```

* templates > authentication > new_password.html


```html
<form class="border border-light p-5" id="validation-form" action="{% url 'reset_user_password' uidb64 token %}"
  method="POST">

  <p class="h4 mb-4 text-center ">Set New Password</p>

  {% csrf_token %}
  {% include 'partials/_messages.html' %}

  <!-- Password -->
  <div class="col">
    <input type="password" id="passwordField" name="password" class="form-control mt-4" placeholder="Password *">
  </div>

  <!-- Confirm Password -->
  <div class="col">
    <input type="password" id="" name="confirm_password" class="form-control mt-4"
      placeholder="Confirm Password *">
  </div>

  <!-- Set Password button -->
  <button class="btn btn-info my-4 btn-block" name="set_password" type="submit">
    Set Password
  </button>

  <!-- Sign In -->
  <p class="text-center">Already have an account?
    <a href="{% url 'signin' %}">Sign In</a>
  </p>
</form>
```

* authentication > views.py

```python
from django.urls import reverse
from django.contrib.auth.tokens import PasswordResetTokenGenerator


class RequestPasswordResetEmail(View):
    def get(self, request):
        if request.user.is_authenticated:
            return redirect('home')
        else:
            return render(request, 'authentication/reset_password.html')

    def post(self, request):
        email = request.POST['email']
        context = {
            'email': email,
            'values': request.POST
        }
        if not User.objects.filter(email=email).exists():
            messages.error(request, 'Please enter your correct email address')
            return render(request, 'authentication/reset_password.html')

        user = User.objects.filter(email=email)
        current_site = get_current_site(request)

        if user.exists():
            email_contant = {
                'user': user[0],
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
                'token': PasswordResetTokenGenerator().make_token(user[0]),
            }
            link = reverse('reset_user_password', kwargs={
                'uidb64': email_contant['uid'], 'token': email_contant['token']})

            email_subject = 'Password Reset Instructions'
            reset_url = 'http://'+current_site.domain+link

            email = EmailMessage(
                email_subject,
                'Hi there, Please click the link below to reset your password \n'+reset_url,
                'noreply@semycolon.com',
                [email],
            )
            EmailThread(email).start()
            return render(request, 'authentication/reset_password.html', context)

        return render(request, 'authentication/reset_password.html', context)


class CompletePasswordReset(View):
    def get(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token
        }
        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))

            user = User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.info(request, 'Password reset link is invalid, please request a new one')
                return redirect('reset_password')

        except DjangoUnicodeDecodeError as identifier:
            messages.success(request, 'Invalid link')
            return render(request, 'authentication/new_password.html')
        return render(request, 'authentication/new_password.html', context)

    def post(self, request, uidb64, token):
        context = {
            'uidb64': uidb64,
            'token': token,
        }
        password = request.POST['password']

        try:
            user_id = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()

            messages.success(
                request, 'Password reset success, you can sign in with new password')
            return redirect('signin')

        except DjangoUnicodeDecodeError as identifier:
            messages.error(request, 'Something went wrong')
            return render(request, 'authentication/new_password.html', context)

        return render(request, 'authentication/new_password.html', context)

```

* authentication > urls.py

```python
urlpatterns = [
    path('reset_password/', RequestPasswordResetEmail.as_view(), name="reset_password"),
    path('set_new_password/<uidb64>/<token>', CompletePasswordReset.as_view(), name='reset_user_password'),
]
```

* templates > authentication > signin.html

```django
<div>
  <!-- Forgot password -->
  <a href="{% url 'reset_password' %}">Forgot password?</a>
</div>
```

## Run This Demo -

Steps:

1. Clone/pull/download this repository
2. Create a virtualenv with `virtualenv venv` and install dependencies with `pip install -r requirements.txt`
3. Configure your .env variables
5. Collect all static files `python manage.py collectstatic`
