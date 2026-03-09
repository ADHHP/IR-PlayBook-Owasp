# IR Playbook: IDOR (Insecure Direct Object Reference)

## 1. Incident Overview

**Incident Name:** Insecure Direct Object Reference (IDOR) Exploitation

**Description:**

IDOR xảy ra khi ứng dụng web cho phép người dùng truy cập trực tiếp vào tài nguyên bằng cách thay đổi **ID/Reference** mà không có kiểm tra authorization phù hợp.

Ví dụ:

```
https://example.com/api/user/123
```

Attacker có thể thay đổi:

```
https://example.com/api/user/124
https://example.com/api/user/125
```

để truy cập dữ liệu của người khác.

**Impact có thể xảy ra:**

- Lộ dữ liệu cá nhân (PII)
- Lộ thông tin tài khoản
- Lộ invoice / đơn hàng
- Lộ tài liệu nội bộ
- Lộ dữ liệu nhạy cảm của doanh nghiệp

**Severity:**

High – Critical (tùy mức độ dữ liệu bị truy cập)

# 2. Preparation

### 2.1 Logging

- Web access logs
- Application logs
- Authentication logs
- API gateway logs
- WAF logs

Ví dụ log:

```
timestamp
user_id
session_id
request_ip
request_uri
response_code
```

### 2.2 Monitoring Rules (SIEM)

Ví dụ detection rule:

```
IF same user requests multiple sequential IDs
AND response code = 200
THEN alert possible IDOR enumeration
```

Ví dụ query:

```
request_uri:*user/*
| stats count by src_ip
| where count > 50
```

### 2.3 Tools

| Tool | Purpose |
| --- | --- |
| SIEM (ELK/Wazuh) | Log analysis |
| Burp Suite | Reproduce vulnerability |
| WAF | Block attack |
| Database logs | Check data access |
| Ticketing (Jira) | Incident tracking |

# 3. Detection & Analysis

## 3.1 Detection Sources

Incident có thể được phát hiện từ:

- SOC alert
- Bug bounty report
- Pentest report
- Customer complaint
- WAF alert

## 3.2 Initial Triage

SOC analyst xác định:

- Endpoint bị khai thác
- User ID bị truy cập
- Attacker IP
- Session token

Ví dụ suspicious request:

```
GET /api/user/101
GET /api/user/102
GET /api/user/103
GET /api/user/104
```

## 3.3 Log Analysis

Phân tích:

```
src_ip
user_agent
session_id
user_id
endpoint
```

Ví dụ query ELK:

```
request_uri:"/api/user/*"
| stats count by src_ip
```

## 3.4 SIEM detection rule cho IDOR (Wazuh)

### 3.4.1. Ý tưởng phát hiện IDOR trong SIEM

Hành vi phổ biến khi khai thác IDOR:

- Một IP gửi nhiều request tới **cùng endpoint**
- ID thay đổi liên tục
- Request trong thời gian ngắn
- Nhiều response **200 OK**

Ví dụ log:

```
192.168.1.10 - - "GET /api/user/101" 200
192.168.1.10 - - "GET /api/user/102" 200
192.168.1.10 - - "GET /api/user/103" 200
192.168.1.10 - - "GET /api/user/104" 200
```

Đây là dấu hiệu **ID enumeration**.

### 3.4.2. Wazuh Log Decoder (parse endpoint ID)

File:

```
/var/ossec/etc/decoders/local_decoder.xml
```

Decoder để extract **API endpoint và ID**:

```
<decodername="idor-api">
<prematch>GET /api/user/</prematch>
</decoder>

<decodername="idor-api-id">
<parent>idor-api</parent>
<regex>GET /api/user/([0-9]+)</regex>
<order>object_id</order>
</decoder>
```

Decoder này sẽ trích xuất:

```
object_id = 101
object_id = 102
```

### 3.4.3. Wazuh Detection Rule

File:

```
/var/ossec/etc/rules/local_rules.xml
```

Rule phát hiện **ID enumeration**:

```
<groupname="web,idor">

<ruleid="100500"level="10">
<if_sid>idor-api-id</if_sid>
<description>Possible IDOR attempt - accessing sequential user IDs</description>
<group>idor,web_attack</group>
</rule>

</group>
```

### 3.4.4. Rule phát hiện nhiều request trong thời gian ngắn

Rule nâng cao: phát hiện **nhiều request cùng IP**.

```
<ruleid="100501"level="12"frequency="10"timeframe="60">
<if_sid>100500</if_sid>
<same_source_ip/>
<description>Possible IDOR enumeration attack detected</description>
<group>idor,web_attack,enumeration</group>
</rule>
```

Ý nghĩa:

| Parameter | Meaning |
| --- | --- |
| frequency=10 | 10 request |
| timeframe=60 | trong 60 giây |
| same_source_ip | cùng IP |

Alert nếu:

```
1 IP → >10 request /api/user/*
trong 60s
```

### 3.4.5. Rule phát hiện truy cập nhiều object khác nhau

Rule nâng cao hơn:

```
<ruleid="100502"level="13"frequency="15"timeframe="120">
<if_sid>idor-api-id</if_sid>
<same_source_ip/>
<description>High confidence IDOR exploitation</description>
<group>idor,web_attack,critical</group>
</rule>
```

### 3.4.6. Ví dụ Alert Wazuh

Alert sinh ra:

```
{
 "rule": {
  "id":"100501",
  "description":"Possible IDOR enumeration attack detected",
  "level":12
 },
 "srcip":"192.168.1.10",
 "url":"/api/user/104",
 "group": ["idor","web_attack"]
}
```

### 3.4.7. Wazuh Active Response (Block attacker)

Có thể tự động block IP bằng firewall.

Rule:

```
<active-response>
<command>firewall-drop</command>
<location>local</location>
<rules_id>100501</rules_id>
</active-response>
```

Sau khi trigger:

```
iptables -A INPUT -s attacker_ip -j DROP
```

### 3.4.8. Detection cho API khác

Ví dụ endpoint:

```
/api/order/ID
/api/invoice/ID
/api/document/ID
```

Regex:

```
<regex>GET /api/(user|order|invoice)/([0-9]+)</regex>
```

### 3.4.9. Threat Hunting Query (Wazuh / OpenSearch)

Tìm dấu hiệu IDOR:

```
data.url: "/api/user/*"
| stats count by srcip
| where count > 50
```

Hoặc:

```
srcip AND /api/user/*
```

## 3.5 Xác định mức độ khai thác

Câu hỏi cần trả lời:

- Attacker truy cập bao nhiêu object?
- Dữ liệu gì bị truy cập?
- Có tải xuống dữ liệu không?
- Có automation không?

## 3.6 Decision Tree

```
IF attacker accessed < 10 records
    → Low impact

IF attacker accessed 10–100 records
    → Medium impact

IF attacker accessed > 100 records
    → High impact
```

# 4. Containment

## 4.1 Immediate Containment

Các hành động cần thực hiện ngay:

- Block attacker IP trên WAF
- Disable compromised session
- Tạm thời disable endpoint vulnerable

Ví dụ WAF rule:

```
BLOCK src_ip = attacker_ip
```

## 4.2 Session Revocation

Invalidate session token:

```
DELETE FROM sessions WHERE user_id = X
```

## 4.3 Rate Limiting

Áp dụng limit cho endpoint:

```
/api/user/*
```

Ví dụ:

```
limit: 10 requests/minute
```

# 5. Eradication

## 5.1 Root Cause

Ứng dụng không kiểm tra authorization.

Ví dụ code vulnerable:

```python
user = db.get_user(user_id)
return user
```

## 5.2 Fix Implementation

Phải kiểm tra **ownership**:

```python
user = db.get_user(user_id)

if user.id != current_user.id:
    return 403
```

## 5.3 Best Practice

- **Object-level authorization**
- **Access control middleware**
- **UUID thay vì sequential ID**

Ví dụ:

```
/api/user/7f4e9c21-9b23-4a12
```

# 6. Recovery

## 6.1 Deploy Patch

- Fix code
- Deploy hotfix
- Restart service

## 6.2 Validate Fix

Security team kiểm tra lại bằng:

- Burp Intruder
- Manual testing
- Automated scanner

Test case:

```
User A cannot access User B data
```

## 6.3 Monitoring sau khi fix

Theo dõi logs:

```
403 responses
authorization errors
```

# 7. Evidence Collection

Thu thập các artifact sau:

### Logs

- Web access logs
- API logs
- WAF logs
- Authentication logs

### Network

- Source IP
- Geo location
- ASN

### Application

- User IDs accessed
- Endpoint used
- Data exported

# 8. Incident Reporting

## 8.1 Incident Summary

```
Incident Name: IDOR Exploitation
Date Detected:
Affected Endpoint:
Affected Data:
Severity:
```

## 8.2 Impact Assessment

Ví dụ:

```
120 user profiles accessed
Email addresses exposed
Phone numbers exposed
```

## 8.3 Root Cause

```
Missing authorization check in API endpoint
```

## 8.4 Remediation

- Implement object-level access control
- Add authorization middleware
- Implement rate limiting

# 9. Lessons Learned

Sau incident cần:

### Security Improvements

- Mandatory authorization checks
- API security review
- Secure coding training

### Detection Improvements

Thêm rule:

```
IF sequential object ID access detected
THEN alert IDOR enumeration
```

### Process Improvements

- Code review checklist
- API security testing trong CI/CD
- Pentest định kỳ

# 10. Automation (SOAR Playbook)

Workflow tự động:

```
SIEM Alert
      ↓
Create Incident Ticket
      ↓
Check log correlation
      ↓
Block attacker IP
      ↓
Notify Security Team
```

# 11. Escalation Matrix

| Level | Action |
| --- | --- |
| SOC Tier 1 | Detect alert |
| SOC Tier 2 | Investigate logs |
| App Security | Fix vulnerability |
| DevOps | Deploy patch |
| CISO | Incident report |

# 12. Severity Classification

| Severity | Condition |
| --- | --- |
| Low | <10 records accessed |
| Medium | 10–100 records |
| High | >100 records |
| Critical | Sensitive data leaked |

# 13. Checklist (Quick Response)

Checklist cho SOC:

```
[ ] Identify vulnerable endpoint
[ ] Identify attacker IP
[ ] Block attacker
[ ] Disable session
[ ] Analyze logs
[ ] Notify development team
[ ] Deploy fix
[ ] Verify fix
[ ] Write incident report
```