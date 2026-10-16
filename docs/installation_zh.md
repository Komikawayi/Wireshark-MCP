# 安装、更新与卸载

安装分两步：安装 Python 包，再把服务配置加入选定客户端。配置写入成功不等于客户端已经连接；重启/刷新客户端并运行 `wireshark-mcp doctor` 检查依赖。

```sh
pip install wireshark-mcp
wireshark-mcp install                    # 交互式选择
wireshark-mcp install --client cursor    # 明确目标；默认全局范围
```

## 项目级配置

```sh
wireshark-mcp install --client codex --scope project --dry-run
wireshark-mcp install --client codex --scope project
wireshark-mcp install --client cursor --scope project --project-dir /absolute/project
```

项目目录必须已存在，未指定时使用当前目录。只有安装实际落盘时才创建客户端子目录；预览、更新未安装项、卸载未安装项均不创建目录。

| 客户端 | 项目路径 | 服务所在字段 |
|---|---|---|
| Claude Code | `.mcp.json` | `mcpServers` |
| Cursor | `.cursor/mcp.json` | `mcpServers` |
| Codex | `.codex/config.toml` | `mcp_servers` |
| VS Code / Insiders | `.vscode/mcp.json` | 顶层 `servers`，不是全局 settings.json 的 `mcp.servers` |

不支持该范围的客户端会报错，不回退到用户级配置。VS Code 与 Insiders 共用项目文件，选中二者时只写一次。项目路径解析到项目外部或配置文件为符号链接时，安装器保留原文件并报告错误。

Codex 仅对受信任项目加载项目配置；安装器不修改项目信任设置，见 [官方配置说明](https://learn.chatgpt.com/docs/config-file/config-basic)。生成的 stdio 配置固定使用当前机器的 Python 和工具路径；不要把机器专属环境直接当作跨机器可复用模板提交。

## 自动化与预览

```sh
wireshark-mcp install --client cursor --client codex --dry-run --format json
wireshark-mcp install --client cursor --client codex --format json
wireshark-mcp install --client all --dry-run --format json
```

无 TTY 或输出为 JSON 时，写操作须显式给出 `--client`；`--client all` 是明确批量选择。未选择目标时退出 2，不再默认修改所有检测到的客户端。无目标的 `--dry-run` 可以预览全部候选，不写配置、目录或备份。

JSON 包含 `action`、`scope`、`dry_run`、逐客户端 `status/path/backup_path`，以及 `summary.changed/planned/errors/skipped`。`planned` 不是已配置数量；`not_detected` 与 `not_installed` 不是连接成功。全局范围仍只处理已存在的客户端配置目录。

## 更新和卸载

```sh
pip install --upgrade wireshark-mcp
wireshark-mcp update --client codex --scope project
wireshark-mcp uninstall --client codex --scope project --dry-run
wireshark-mcp uninstall --client codex --scope project
```

`update` 只刷新已有条目，不安装缺失项；它不是 Python 包升级命令。重复安装相同配置不重写文件、不刷新 mtime、不新增备份。安装器刷新自身启动字段，同时保留其他服务、用户设置、本条目的自定义超时及非冲突环境变量。卸载只删除该服务条目，不卸载 Python 包或 Wireshark。

JSON 使用结构校验；TOML 使用解析器编辑，支持带引号的表名，保留无关注释、表及多行字符串。损坏文件和错误的对象/表结构按客户端报告错误，保持原字节不变。

## 备份与恢复

已有配置确实需要修改时，安装器先在同目录创建独占的 `*.wireshark-mcp-*.bak`，保存完整修改前字节，并在结果中返回其路径。备份可能包含原配置中的凭据，应按原配置保管；不自动清理备份。

恢复前先确认当前文件没有后续需要保留的编辑，再将对应备份复制回结果中的 `path`。恢复的是整份文件，不是只合并本服务条目。新建配置没有修改前备份；卸载后保留配置文件及其他内容。

每份配置以临时文件加原子替换写入；多个客户端不是全有或全无的事务。部分失败时检查逐客户端结果与备份，再重试失败项。

- 退出 0：处理完成或只读预览通过，可能全部 unchanged/skipped；不代表连接已验证。
- 退出 1：至少一个配置读取、校验或写入失败；其他客户端可能已经成功。
- 退出 2：参数、客户端选择或范围错误，未开始批量配置。

## 借鉴来源与插件分发

客户端选择与安装范围参考固定版本的 [ida-pro-mcp 安装器](https://github.com/mrexodia/ida-pro-mcp/blob/c133c3853faa111a9b00ee615c013b720d0c4acd/src/ida_pro_mcp/installer.py)。并行实现的 [插件分发路线](plugin-installation_zh.md) 已打包项目和两个 Skills；同一客户端选择一种注册方式。本地验证与远端发布分别记录。
