# 实现设计

本文描述模块、接口与数据访问设计。当前已实现管理后台、双监听 MCP、通用协议工具及文件中转；各协议的具体边界见[协议使用说明](protocols.md)，运行方式见 [开发与打包说明](development.md)。

## 1. 产品结构

采用三个源码模块，运行两个独立后端进程：

- **Admin**：Iris 后端，提供管理员认证和配置管理 API。
- **Admin Web**：React、Vite、TypeScript 和 Arco Design 管理页面，管理密钥、访问策略、系统连接及代理器。
- **MCP**：供 agent 发现连接、调用工具；提供两个端口：内网端口免密钥认证，另一个端口强制使用密钥。内网端口可按需增加 IP/CIDR 访问限制。

Go 后端配合官方 MCP Go SDK；Admin Web 独立构建为静态资源，由 Nginx 托管。两个后端进程共享SQLite 或 PostgreSQL 配置库，使用 WAL 模式，仅由 Admin 负责本地 schema 迁移。服务自身的本地配置库使用 GORM 和 Go model；外部 SQL 数据库通过对应驱动访问。协议适配器、代理拨号、连接池及必要会话均为进程内部模块。RDP 如需 guacd 等协议组件，作为内部依赖接入。

## 2. 调用路径

MCP 客户端 → 对应监听端口的认证策略 → 连接权限检查 → 协议适配器 → 代理器或直连 → 目标系统。

Admin → 更新配置库 → 后续请求使用新配置。更新代理器或连接凭据后，关闭或淘汰旧连接池及相关会话。

入口监听和目标连接相互独立：监听端口决定调用认证方式，系统连接绑定的代理器决定出站路径。

## 3. 管理控制台

### 密钥管理

- 创建、命名、禁用、删除密钥，可设置有效期。
- 创建时显示完整密钥一次，数据库保存校验摘要，列表仅展示前缀。
- 可为密钥选择允许使用的系统连接；默认行为在界面中明确展示。
- MCP 使用 Authorization: Bearer <key>；适配支持自定义认证头的客户端。

### 内网免认证

- 提供独立的免认证 MCP 端口，仅绑定指定内网地址，并限制网络可达范围；可按需增加 IP/CIDR 白名单。
- 配置免认证端口可用的系统连接，作为一个固定的内网访问权限集合。
- 免认证仅作用于 MCP；Admin 始终需要独立管理员登录。
- 白名单匹配使用可信的连接源地址，不接受客户端自行提交的 X-Forwarded-For 等头作为依据。

MCP 进程提供两个监听地址：免认证监听绑定指定内网地址；密钥认证监听对每次请求校验密钥。两者使用相同的工具实现。

认证策略由请求进入的监听端口决定，不依据来源 IP 将密钥认证端口降级为免认证。配置反向代理时，仅将需要密钥的入口转发到密钥认证监听；转发后的 loopback 来源不改变认证策略。

### 系统连接

配置项：名称、分组、协议类型、目标地址、端口、认证信息、代理器、TLS/SSH 主机校验、超时、启用状态。

按协议展示专属字段，例如 SQL 数据库名、MongoDB 数据库及认证库、Redis DB、SSH 私钥、kubeconfig、RDP 域及分辨率，以及 HTTPS 基础 URL、请求头和认证配置。密码和私钥加密保存，主密钥放在数据库之外；管理列表和 MCP 结果不回传完整凭据。

提供保存、编辑、删除及连接测试。测试应分别显示网络可达、协议认证、操作是否成功。

### 代理器

- 类型：HTTP CONNECT、HTTPS CONNECT、SOCKS5、SSH 隧道。
- 配置：名称、地址、端口、认证、证书/主机密钥校验、超时、DNS 解析方式。
- 系统连接选择一个代理器，未选择则直连。
- 常见多跳组合通过代理器的“上游代理器”配置表达，保存时禁止循环引用，并限制链路深度。
- 支持代理测试及“通过这个代理器连接指定系统”的完整路径测试。

调用记录作为一个简单列表：时间、密钥或内网身份、系统连接、工具、耗时、结果状态。默认不保存完整查询结果、密码、文件或屏幕内容。

## 4. MCP 服务

远程传输使用 Streamable HTTP，两个端口使用相同的 /mcp 路径和工具实现，仅入口认证策略不同。

基本流程：按监听端口执行密钥认证或免认证访问策略 → 校验可用连接 → 根据 connection_id 加载连接及代理配置 → 调用协议适配器 → 返回受大小限制的结果。

建议工具：

- connections_list、connection_test。
- db_tables、db_schema、db_query；写操作使用单独授权的 db_execute。
- mongo_collections、mongo_find、mongo_count、mongo_aggregate；写入使用单独授权的 mongo_insert、mongo_update、mongo_delete。
- redis_scan、redis_read、redis_command。
- ssh_exec、sftp_read（规划）。
- files_prepare_upload、files_deliver、files_status、files_remove：通过 S3 兼容存储完成文件上传、目标拉取、状态查询及云端清理。
- k8s_get、k8s_logs、k8s_exec、k8s_apply 等。
- rdp_open、rdp_screenshot、rdp_input、rdp_close。
- https_request：基于已登记连接发起 HTTPS 请求。

agent 使用登记的 connection_id，不在每次调用中携带目标密码或随意指定代理地址。工具发现和实际调用均检查连接权限。有状态会话绑定调用身份及连接，不能仅凭猜测 session_id 访问。

所有调用设置超时、输出大小限制，正确关闭会话和隧道。写操作失败或连接断开后，不自动重试可能已经生效的操作。入口认证密钥与目标系统凭据分开处理。

## 5. 内部协议适配

目标连接使用对应驱动和成熟协议客户端，不给每个系统额外部署 MCP 后端。SQL、MongoDB、Redis、SSH/SFTP、Kubernetes 和 HTTPS 使用成熟驱动或客户端，代理连接统一由内部拨号模块提供。HTTP 代理必须支持 CONNECT；代理出错返回错误，不降级直连。每次连接使用其自身代理配置，不修改进程全局 HTTP_PROXY。

TLS 通过隧道时仍验证原始目标主机名，SSH 校验主机密钥。Redis Cluster/Sentinel、MongoDB 副本集等多节点发现，需要保证发现的节点也经过指定代理。

### 文件上传与 S3 兼容存储

Admin 提供服务级云存储配置：Endpoint、Region、Bucket、Access Key、Secret Key、可选 Session Token、对象前缀、Path Style、代理器和单文件大小上限。凭据加密保存，读取配置不回传密钥。

调用流程：准备文件记录及临时 PUT 地址 → 浏览器或 agent 直接上传至私有存储桶 → 请求目标发送 → 服务端核验对象大小 → 通过 SSH 让目标下载临时 GET 地址 → 校验大小和 SHA-256 → 在目标目录提交文件。

文件记录绑定调用身份、授权连接、绝对目标路径和预期摘要；每次操作重新检查连接权限。目标使用目录内的私有临时文件，校验完成后以不覆盖方式提交，文件权限为 0600。目标需具备 Linux/POSIX SSH、curl 和 sha256sum 等工具，目标目录必须存在。

上传签名有效期 15 分钟，下载签名有效期 5 分钟；记录有效期 24 小时。云端副本通过显式清理或存储桶生命周期删除，删除云端副本不影响目标文件，也不会撤销仍有效的上传签名。目标发送通过条件更新领取一次执行，结果未知时不自动重试。

云存储访问和 SSH 访问分别使用所选代理器；浏览器/agent 上传与目标下载各自使用自身网络。详细字段、CORS、权限、工具及验收范围见 [文件传输说明](file-transfers.md)。

### 本地配置库开发规范

ConnKit 自身的密钥、系统连接、代理器等数据保存在SQLite 或 PostgreSQL 配置库，使用明确的 Go model 和 GORM 完成查询及持久化。自动迁移仅限本服务拥有的配置库。

GORM 和模型查询是服务内部数据访问的开发规范，不约束 MCP 访问目标系统的方式，也不要求为目标数据库生成 Go model。

### 目标 SQL 数据库

连接类型包括 SQLite、MySQL、PostgreSQL，使用对应数据库驱动和适配器。提供表结构发现、SQL 查询和单独授权的 SQL 写操作，保留数据库原生查询语义。

- MySQL、PostgreSQL：在驱动连接或连接池层接入统一代理拨号，支持直连或配置的代理器，不强制经过 GORM。
- SQLite：使用 SQLite 驱动访问服务端登记的本地文件，不经过网络代理；作为目标连接的 SQLite 文件与 ConnKit 自身的配置库分别管理。
- 查询：以 connection_id、SQL 和独立参数值作为输入，使用数据库驱动的参数绑定，参数占位符遵循对应数据库规则。动态标识符单独验证，不把参数值拼接进 SQL。
- 执行：设置 context 超时、最大返回行数和输出大小；区分只读查询与写操作权限，不能仅靠 SQL 前缀识别副作用。
- 表结构：通过目标数据库的元数据接口读取，不执行 AutoMigrate，也不修改目标表结构。

只读需求仍使用数据库账号权限、Redis ACL、Kubernetes RBAC 等落实；SSH 任意命令不声称可以靠黑名单实现只读。

### MongoDB

使用官方 MongoDB Go Driver。配置种子节点、数据库、认证库、认证方式、TLS、连接拓扑和代理器；所有节点连接复用指定的代理拨号策略。

提供集合发现、结构化条件查询、计数及聚合，设置投影、排序、分页、执行时限和返回大小。BSON 特殊类型采用明确的 Extended JSON 编解码规则。写入使用独立授权工具；聚合中的 $out、$merge 等写阶段按写操作授权，不作为只读查询开放。

mongodb+srv 的 DNS SRV/TXT 发现单独处理：TCP 代理拨号不代表 DNS 请求也经代理，需要明确解析路径并验证发现节点的可达性。

### HTTPS 调用

使用 Go HTTP 客户端。连接配置基础 URL、默认请求头、认证信息、TLS/客户端证书、超时和代理器；MCP 参数提供相对路径、方法、查询参数、请求头及请求体。

相对路径解析后仍须限定到配置允许的目标，拒绝通过绝对 URL、跨主机路径或 Host 覆盖绕过连接权限。重定向逐跳检查目标，并且不向未授权目标转发认证信息。认证字段由连接配置注入，普通调用参数不覆盖受保护的认证头。

返回状态码、允许的响应头及受大小限制的响应体，支持 JSON 和文本；二进制结果使用明确编码或受控文件结果。请求体、响应体和 URL 查询参数中的凭据按规则脱敏。HTTPS 是目标连接类型，HTTP/HTTPS CONNECT 是出站代理器类型，两者分别配置。

### Kubernetes 与 RDP

Kubernetes 查询和流式操作分别验证。client-go 文档提示 SOCKS5 对部分 SPDY streaming 端点有限制，需要实测日志、exec 和 port-forward，必要时改走底层 TCP 隧道。导入 kubeconfig 时检查会执行本地程序的 exec 插件。

RDP 需要内部图形会话后端，可复用 Guacamole/FreeRDP。给 agent 提供截图和输入属于适配工作；若还需要人使用浏览器远程桌面，再增加相应页面。会话后端始终放在内部。

## 6. 交付与验收

源码模块为 `mcp/`、`admin/`、`admin-web/`；可执行入口为 `cmd/mcp/` 与 `cmd/admin/`。

GitHub Actions 构建两个镜像：`connkit-mcp` 运行 MCP；`connkit-admin` 包含 Nginx、Admin 后端及 Admin Web 静态资源。Admin 后端在合并镜像内监听 loopback，由 Nginx 转发 `/api/` 请求，并托管前端页面。进程入口负责信号转发及任一子进程退出后的整体停止。

SQLite 模式共享本地配置数据卷；PostgreSQL 模式连接同一独立配置数据库。主密钥通过环境单独注入。具体环境变量、构建触发条件及镜像标签见 [开发与打包说明](development.md)。涉及 RDP 时按需增加内部协议依赖。

实施顺序：

1. Admin 登录、密钥、可选内网 IP 限制、连接和代理器管理。
2. 双端口 MCP、连接发现、统一拨号及连接测试。
3. SQLite/MySQL/PostgreSQL 的目标驱动接入及查询工具，随后完成 SSH、Redis、MongoDB、K8s、HTTPS 适配及真实环境验证。
4. RDP 会话、截图和输入。
5. 验证两个监听端口的访问策略及反向代理转发行为。

最低验收：每种代理的成功与失败路径；代理失败不直连；并发调用不串用代理或凭据；密钥禁用后拒绝调用且既有会话按策略失效；免认证端口只允许预期的内网范围访问；密钥认证端口即使收到 loopback 来源请求也不能免认证；真实查询、命令及桌面操作完成。

## 参考文档

- GORM：https://gorm.io/docs/
- MongoDB Go Driver：https://www.mongodb.com/docs/drivers/go/current/
- Go HTTP 客户端：https://pkg.go.dev/net/http
- MCP Go SDK：https://github.com/modelcontextprotocol/go-sdk
- MCP 传输规范：https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- client-go 代理限制：https://github.com/kubernetes/client-go/blob/master/transport/config.go
- Guacamole：https://guacamole.apache.org/doc/gug/
