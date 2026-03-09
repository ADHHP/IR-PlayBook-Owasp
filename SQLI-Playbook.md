# Untitled

# IR Playbook: SQL Injection Attack

## 1. Incident Overview

**Incident Name:** SQL Injection (SQLi)

**Description:**

SQL Injection xảy ra khi ứng dụng web không kiểm tra và sanitize input của người dùng trước khi đưa vào câu lệnh SQL. Attacker có thể chèn câu lệnh SQL để:

- Bypass authentication
- Truy xuất dữ liệu database
- Thay đổi dữ liệu
- Xóa dữ liệu

Ví dụ payload SQLi:

```sql
' OR '1'='1
```

Ví dụ request:

```
GET /login?username=admin'--&password=test
```

**Impact có thể xảy ra:**

- Rò rỉ dữ liệu database
- Bypass authentication
- Thay đổi hoặc xóa dữ liệu
- Chiếm quyền admin
- Toàn bộ database bị dump

**Severity:**

High – Critical

# 2. Preparation

## 2.1 Logging Requirements

Để phát hiện SQL Injection cần bật logging:

| Log Type | Mục đích |
| --- | --- |
| Web access logs | theo dõi request |
| Application logs | lỗi SQL |
| Database logs | truy vấn bất thường |
| WAF logs | phát hiện payload SQL |

Ví dụ access log:

```
192.168.1.10 GET /product?id=10 UNION SELECT username,password FROM users
```

## 2.2 Security Controls

Các cơ chế bảo vệ cần có:

- Web Application Firewall (WAF)
- Input validation
- Parameterized queries
- Least privilege database account
- SIEM monitoring

## 2.3 SIEM Monitoring Rules

SIEM cần detect các keyword SQL phổ biến:

```
UNION SELECT
OR 1=1
SLEEP(
BENCHMARK(
INFORMATION_SCHEMA
```

# 3. Detection & Analysis

## 3.1 Detection Sources

SQL Injection có thể được phát hiện từ:

- WAF alert
- SIEM alert
- Database error logs
- Pentest report
- Bug bounty report
- User report

## 3.2 Indicators of Compromise (IoC)

Các dấu hiệu SQLi:

| Indicator | Description |
| --- | --- |
| SQL keywords trong URL | UNION SELECT |
| Error-based response | SQL syntax error |
| Time delay | SLEEP() |
| High database queries | brute force query |

## 3.3 Log Analysis

Phân tích access log:

Ví dụ suspicious request:

```
GET /product?id=10 UNION SELECT username,password FROM users
```

Hoặc:

```
GET /login?username=admin' OR '1'='1
```

Các trường cần kiểm tra:

- Source IP
- Request URI
- User-Agent
- Response code
- Timestamp

## 3.4 SIEM Detection Rule (Wazuh)

Ví dụ rule phát hiện SQLi:

File:

```
/var/ossec/etc/rules/local_rules.xml
```

```xml
<group name="web,sqli">

  <rule id="100600" level="10">
    <if_group>web</if_group>
    <match>UNION SELECT</match>
    <description>Possible SQL Injection attempt</description>
    <group>sqli,web_attack</group>
  </rule>

  <rule id="100601" level="10">
    <if_group>web</if_group>
    <match>' OR '1'='1</match>
    <description>SQL Injection authentication bypass attempt</description>
    <group>sqli,web_attack</group>
  </rule>

</group>
```

## 3.5 Impact Assessment

Xác định:

- Có truy cập database không?
- Có dump dữ liệu không?
- Có thay đổi dữ liệu không?

Ví dụ:

| Impact | Severity |
| --- | --- |
| Login bypass | Medium |
| Data exposure | High |
| Database dump | Critical |

# 4. Containment

## 4.1 Immediate Actions

Ngay khi phát hiện SQLi:

- Block attacker IP trên WAF
- Tạm thời disable endpoint vulnerable
- Enable rate limiting
- Alert security team

Ví dụ:

```
iptables -A INPUT -s attacker_ip -j DROP
```

## 4.2 Database Protection

Các bước cần thực hiện:

- Revoke database privileges
- Disable vulnerable query
- Monitor database activity

## 4.3 Session Control

Nếu attacker login thành công:

- Invalidate session
- Reset user credentials

# 5. Eradication

## 5.1 Root Cause Analysis

Nguyên nhân thường gặp:

- Query concatenation
- Không validate input
- Không dùng prepared statements

Ví dụ code vulnerable:

```php
$query = "SELECT * FROM users WHERE username = '$username'";
```

## 5.2 Secure Fix

Sử dụng **prepared statements**.

Ví dụ:

```php
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
$stmt->execute([$username]);
```

## 5.3 Additional Fixes

- Input validation
- ORM framework
- Stored procedures
- Least privilege database account

# 6. Recovery

## 6.1 Deploy Patch

Các bước:

1. Fix code
2. Deploy application patch
3. Restart services

## 6.2 Verify Fix

Security team kiểm tra bằng:

- Burp Suite
- SQLmap
- Manual testing

Test case:

```
' OR '1'='1
```

Kết quả mong đợi:

```
HTTP 403
```

## 6.3 Monitoring

Theo dõi logs:

- SQL errors
- WAF alerts
- abnormal database queries

# 7. Evidence Collection

Thu thập bằng chứng phục vụ forensics.

### Logs

- Web access logs
- Application logs
- WAF logs
- Database logs

### Network

- Source IP
- Geo location
- ASN

### Database

- Query logs
- Exported data
- Account access history

# 8. Incident Reporting

## Incident Summary

```
Incident Name: SQL Injection Attack
Date Detected:
Affected System:
Severity:
```

## Impact Assessment

Ví dụ:

```
Database: users
Records exposed: 1500
Data exposed: email, password hash
```

## Root Cause

```
User input inserted directly into SQL query
```

## Remediation

- Implement prepared statements
- Improve input validation
- Deploy WAF rules

# 9. Lessons Learned

Sau incident cần:

### Security Improvements

- Secure coding training
- Code review
- Automated security testing

### Detection Improvements

Thêm rule SIEM:

```
UNION SELECT
SLEEP(
OR 1=1
```

### Process Improvements

- Security testing trong CI/CD
- Regular penetration testing
- Bug bounty program

# 10. Escalation Matrix

| Level | Responsibility |
| --- | --- |
| SOC Tier 1 | Detect alert |
| SOC Tier 2 | Investigate logs |
| App Security | Analyze vulnerability |
| Dev Team | Fix code |
| CISO | Incident reporting |

# 11. Quick Response Checklist

Checklist nhanh cho SOC:

```
[ ] Identify vulnerable endpoint
[ ] Identify attacker IP
[ ] Block attacker
[ ] Analyze logs
[ ] Assess database access
[ ] Notify development team
[ ] Deploy fix
[ ] Validate fix
[ ] Write incident report
```