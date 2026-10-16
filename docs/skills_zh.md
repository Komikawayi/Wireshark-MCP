# 抓包分析 Skills

项目包含两个可独立使用的 Skill，不要求一次调查同时运行两套流程：

- `wireshark-traffic-analysis`：面向 MCP，涵盖问题驱动诊断、抓包可回答性、协议分支和多文件交接。
- `tshark-cli-analysis`：面向原生 TShark 全能力，包含版本化选项/报告/统计目录、按需参考模块、能力盘点和有界离线执行助手。

源文件统一放在 `skills/`。Codex 通过 `.agents/skills/` 下提交的相对链接发现；Windows Git 若把链接检出为普通文件，运行同步命令生成真实目录。Claude/Copilot 镜像由脚本生成，不另行维护内容：

```sh
python scripts/sync_skills.py
python scripts/sync_skills.py --check --require-installed
```

脚本只写当前仓库的三处发现目录与 manifest，不修改用户级 Skill 或 MCP 配置。`--check --source-only` 仅验证源清单，不宣称客户端已安装；普通检查会明确报告未安装目录。客户端列表未刷新时重启/刷新，并确认两个 Skill 可以被显式选择。

wheel 包含两个 Skill 及助手脚本，但放进 site-packages 不等于客户端完成注册。可使用仓库发现命令，或通过客户端支持的机制安装选定 Skill 目录；本次改动没有宣称发布到公共插件市场。

CLI 能力目录有明确版本边界，不能冻结未来所有插件行为。通常直接使用 SKILL.md 的任务路由；陌生能力再读 `references/capability-map.md`，精确选项查独立的 `references/option-index.md`。升级引擎/插件后运行 `scripts/tshark_inventory.py --check`；新增项须核对文档和测试。实际行为门禁见 [Agent 评测](agent-evaluation_zh.md)。

## 首次安装验证

在新虚拟环境中安装构建出的 wheel 后，从仓库调用检查器，并指定新环境的 Python：

```sh
python scripts/check_skill_installation.py --python /absolute/path/to/venv/bin/python --require-engine --output installed-skills.json
```

Windows 使用新环境的 `Scripts/python.exe`。检查器以 `-I` 从临时工作目录加载已安装包，验证两个 Skill 的资源/引用、三种临时发现布局、缺失引擎的真实错误，以及原生助手与实际注册 MCP 工具的首次离线查询。临时目录中的发现副本不是用户级安装；检查器不更改用户配置，也不证明客户端 UI 已刷新或模型自动选中了正确 Skill。

缺少 TShark 时，省略 `--require-engine` 只允许资源检查通过，报告明确保留 `engine_smoke=not_run:missing_tshark`；完整首次使用验证应保留该参数。先安装 Wireshark CLI 工具，并用 `wireshark-mcp doctor --format json` 检查路径。MCP 可设置 `WIRESHARK_MCP_TSHARK_PATH`；原生助手接受 `--tshark` 的显式路径。模拟不存在的引擎路径用于验证错误恢复，不表示测试主机真的没有安装 TShark。

CI 的 Linux/Windows 引擎任务执行完整安装查询；三系统打包任务执行资源/发现布局检查，并按真实引擎可用性报告跳过项。配置 CI 不等于这些远端任务已经运行。
