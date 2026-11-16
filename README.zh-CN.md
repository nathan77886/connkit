# ConnKit

**基于 MCP，为 AI agent 提供统一的系统连接服务。**

[English](README.md) · [简体中文](README.zh-CN.md)

ConnKit 通过一个管理控制台集中管理系统连接、凭据和出站代理，再通过 [Model Context Protocol（MCP）](https://modelcontextprotocol.io/) 提供操作接口，让 agent 通过统一入口访问数据库、服务器、Kubernetes 集群、远程桌面和 HTTPS API。

> **项目状态：** 早期开发阶段。已实现 Admin、双端口 MCP、SQL/SSH/Redis/MongoDB/HTTPS/Kubernetes 资源操作，以及 S3 中转的 SSH 文件发送。RDP 测试、桌面、截图及输入已通过内置 FreeRDP 实现；Kubernetes 流式操作仍待实现，部署前需完成真实目标验收。

## 开始了解

参阅[开发与打包说明](docs/development.md)（英文），了解本地运行、环境变量、MCP 接入和容器使用方式。[实现设计](docs/architecture.md)描述完整的功能目标。

当前已实现：管理员认证、加密连接与代理链配置、API 密钥编辑/启停/撤销、免认证 CIDR 策略、连接测试、调用记录、各协议操作工具及 S3 中转文件发送。具体配置、示例、工具及限制见[协议使用说明](docs/protocols.md)（英文）。

## 功能与规划

### 管理控制台

支持简体中文与英文，首次打开跟随浏览器语言，并记住语言选择。登录页和顶部导航均可切换，切换时保留表单中未保存的内容。

- 管理系统连接、凭据、分组及连接参数。
- 创建、设置有效期、禁用和撤销 API 密钥，指定密钥可访问的连接。
- 配置免认证端口可访问的连接，以及可选的 IP/CIDR 访问限制。
- 管理出站代理器及上游代理链。
- 测试网络连接和认证，查看工具调用记录。

### MCP 服务

- 使用 Streamable HTTP，两个独立监听端口共用 `/mcp` 路径。
- 密钥认证端口使用 `Authorization: Bearer <key>`。
- 免认证端口用于可信网络，可增加 IP/CIDR 访问限制。
- 使用已登记的连接 ID 发现连接并调用各协议工具。
- 提供连接权限检查、请求超时、结果大小限制和会话清理。

### 连接类型

- **SSH：** 文件先上传至 S3 兼容存储，再由目标端下载并校验 SHA-256；已支持显式开启后的远程命令和有大小限制的 SFTP 读取。
- **Kubernetes：** 资源查看、有限日志读取、服务端 apply 和删除；exec/流式功能尚未实现。
- **RDP：** 远程桌面会话、截图和键鼠输入。
- **MongoDB：** 集合发现、文档查询、聚合及授权写入。
- **Redis：** Key 扫描、数据访问及授权命令调用。
- **MySQL / PostgreSQL：** 通过原生数据库驱动查看表结构、执行参数化 SQL 查询及授权写入。
- **SQLite：** 访问在 ConnKit 服务端登记的数据库文件。
- **HTTPS：** 调用已配置的 API 地址，使用连接级认证、请求头和 TLS 设置。

### 文件上传

配置私有的 S3 兼容存储桶，通过临时 PUT 地址直接上传文件，再由授权的 SSH 目标通过临时 GET 地址下载。存储密钥保留在服务端；目标文件经过校验，不覆盖已有文件。配置、CORS、目标环境要求和 MCP 工具见[文件传输说明](docs/file-transfers.md)（英文）。

### 出站代理

- 直连。
- HTTP CONNECT 和 HTTPS CONNECT 代理。
- SOCKS5 代理。
- SSH 隧道。
- 通过上游代理器引用配置代理链。

每个连接独立选择代理配置。代理失败时向调用方返回错误，不自动降级直连。SQLite 文件访问不经过网络代理。

## 架构

ConnKit 采用三个源码模块、两个后端进程的结构：

- **Admin：** Iris 管理 API 和管理员认证。
- **Admin Web：** React/Vite/Arco Design 管理控制台。
- **MCP：** 为 agent 提供工具，内部使用原生驱动和协议客户端。

工具调用依次经过监听端口的认证策略、连接权限检查和协议适配器，再通过直连或指定代理访问目标。两个 MCP 端口共用工具实现，各自保持独立的认证策略。

技术方案采用 Go、官方 MCP Go SDK、React、Vite、Arco Design 和共享的SQLite 或 PostgreSQL 配置库。**GORM 和 Go model 仅用于 ConnKit 自身配置数据的访问规范。** 目标数据库使用对应驱动，保留原生查询语义。RDP 按需接入内部图形协议后端。

GitHub Actions 配置为构建两个镜像：`connkit-mcp` 运行 MCP；`connkit-admin` 包含 Nginx、Admin 后端和编译后的 Admin Web 静态资源。两个后端进程共享本地配置数据卷，Admin 负责初始化表结构。镜像需在工作流实际运行成功后才会发布。

详细说明见[实现设计](docs/architecture.md)。

## 访问与凭据

- 管理控制台始终要求管理员认证。
- API 密钥和目标系统凭据分别管理。
- API 密钥保存校验摘要；目标密码和私钥加密保存，加密主密钥置于配置数据库之外。
- 免认证端口用于可信网络；反向代理应将需要认证的访问转发到密钥认证端口。
- 监听端口的认证策略不因转发来源或 loopback 地址而改变。
- 目标系统权限由数据库角色、Redis ACL、Kubernetes RBAC 和操作系统账号等机制约束。
- 调用记录默认不保存完整凭据及结果内容。

## 文档

- [S3 兼容存储文件传输](docs/file-transfers.md)（英文）
- [开发与打包说明](docs/development.md)（英文）
- [English overview](README.md)
- [简体中文概览](README.zh-CN.md)
- [实现设计](docs/architecture.md)

## 参与贡献

欢迎通过 [Issue](https://github.com/nathan77886/connkit/issues) 和 Pull Request 提交设计反馈、协议需求、问题报告及文档改进。实现提案请说明预期行为、涉及的连接类型、代理需求和验证方法。示例和报告中请使用脱敏数据，避免包含凭据或私人环境信息。

## 许可证

本项目采用 [MIT 许可证](LICENSE)。

## 1Panel

新增 `onepanel` 连接类型，支持 1Panel v2 面板账号密码、API Key 或已有会话认证，提供 API 读取、容器日志和显式授权的容器终端命令。HTTP 面板需设置 `allow_http:true`；写入和命令默认关闭。详见 [协议文档](docs/protocols.md#1panel-v2)。
