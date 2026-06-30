# Security Testing Toolkit (网络安全测试辅助工具集)

轻量化命令行工具集，覆盖端口探测、资产信息采集、批量漏洞验证全流程。

> ⚠️ **仅用于授权测试环境与实训靶场。** 未经授权对他人系统进行扫描/测试属于违法行为。

## 功能模块

| 模块 | 功能 | 命令 |
|------|------|------|
| **端口扫描** | TCP全端口/指定端口扫描，服务版本指纹识别，OS探测 | `scan` |
| **资产采集** | WHOIS、DNS、ICP备案、IP归属地、CMS指纹、子域名枚举 | `recon` |
| **漏洞验证** | 信息泄露、弱口令、目录遍历批量验证，风险等级判定 | `verify` |
| **报告导出** | Excel资产台账 + 漏洞清单，符合测试报告规范 | `full` / `export` |

## 安装

```bash
cd security-toolkit
pip install -r requirements.txt
```

## 快速开始

### 1. 端口扫描

```bash
# 扫描常用端口
python main.py scan --target 192.168.1.1 --ports top20

# 全端口扫描（限速）
python main.py scan --target 192.168.1.1 --ports 1-65535 --rate 50

# 从文件批量扫描
python main.py scan --target targets.txt --ports web

# 指定端口范围
python main.py scan --target example.com --ports 80,443,8000-8100
```

### 2. 资产信息采集

```bash
# 全量信息采集
python main.py recon --target example.com --modules all

# 仅采集特定信息
python main.py recon --target example.com --modules whois,dns,cms

# 批量采集（从文件）
python main.py recon --target domains.txt --output results.json
```

### 3. 漏洞批量验证

```bash
# 全部检查
python main.py verify --targets http://example.com --checks all

# 仅信息泄露检查
python main.py verify --targets targets.txt --checks info_leak

# 弱口令检查（指定登录路径）
python main.py verify --targets targets.txt --checks weak_pwd --login-path /admin/login
```

### 4. 全流程测试（一键）

```bash
# 完整的扫描→采集→验证→导出流程
python main.py full --target example.com --output report
```

### 5. 结果导出

```bash
# JSON转Excel
python main.py export --input results.json --output report.xlsx

# 导出为JSON
python main.py export --input results.json --output report --format json
```

## 端口预设

| 预设 | 说明 |
|------|------|
| `top20` | 最常用的20个端口 |
| `top1000` | 最常用的1000个端口（默认） |
| `web` | Web服务相关端口 |
| `database` | 数据库服务端口 |
| `remote` | 远程管理端口 |
| `mail` | 邮件服务端口 |
| `file` | 文件共享端口 |
| `all` | 全部65535个端口 |

## 支持的漏洞检查项

| 检查项 | 说明 |
|--------|------|
| `info_leak` | 信息泄露（.git、.env、备份文件、Swagger、Actuator等20+检测项） |
| `weak_pwd` | 弱口令检测（Web登录、FTP、Redis未授权、MongoDB未授权等） |
| `dir_traversal` | 目录遍历（路径穿越、文件包含） |

## 风险等级

| 等级 | 说明 |
|------|------|
| 严重 | 可直接获取系统控制权或大量敏感数据 |
| 高危 | 可获取重要敏感信息或未授权访问 |
| 中危 | 有限度的信息泄露或配置缺陷 |
| 低危 | 轻微信息泄露，需结合其他漏洞利用 |
| 信息 | 仅作为参考信息，不构成直接威胁 |

## 项目结构

```
security-toolkit/
├── config/
│   ├── settings.py            # 全局配置
│   └── fingerprints/
│       ├── services.json      # 服务指纹库
│       └── cms.json           # CMS指纹库
├── scanner/
│   ├── port_scanner.py        # TCP端口扫描引擎
│   ├── service_fingerprint.py # HTTP服务指纹识别
│   └── os_fingerprint.py      # OS探测
├── recon/
│   ├── domain_info.py         # WHOIS/DNS/ICP查询
│   ├── ip_geo.py              # IP归属地查询
│   ├── cms_detect.py          # CMS指纹识别
│   └── subdomain_enum.py      # 子域名枚举
├── verify/
│   ├── risk_engine.py         # 风险评估引擎
│   ├── check_info_leak.py     # 信息泄露检查
│   ├── check_weak_pwd.py      # 弱口令检查
│   └── check_dir_traversal.py # 目录遍历检查
├── output/
│   ├── data_processor.py      # 数据聚合处理
│   └── excel_exporter.py      # Excel报表导出
├── utils/
│   ├── logger.py              # 日志管理
│   └── helpers.py             # 通用工具函数
├── main.py                    # CLI入口
├── requirements.txt
└── README.md
```

## 导出报告说明

生成的Excel报告包含三个工作表：

1. **报告摘要** — 测试概况、统计数据、目标列表
2. **资产台账** — 详细资产信息（端口、服务、CMS、域名、ICP、地理位置等）
3. **漏洞清单** — 按风险等级排列的漏洞详情（含CVSS评分、证据、修复建议）

## 技术栈

- Python 3.x
- socket — TCP端口探测与Banner抓取
- requests — HTTP请求与信息采集
- BeautifulSoup4 — HTML解析
- pandas / openpyxl — Excel数据处理与导出
- dnspython — DNS记录查询
- argparse — 命令行参数解析
