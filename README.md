# CEP 盲写自动补丁工具

> [!WARNING]
> **使用本工具前请知悉并同意以下信息：**
> 1. 修改BIOS/ROM理论上存在导致设备无法启动、硬件损坏的风险。
> 2. 本工具**不是**Intel、AMI或任何主板厂商的官方工具，与上述公司无任何关联。
> 3. 作者不对因使用本工具导致的任何直接或间接损失承担责任。**如果你不确定自己在做什么，请不要使用。**
> 4. 关闭CEP会移除Intel原厂的电压保护机制，**未通过稳定性测试工具测试，可能引发蓝屏或重启**。


## 快速使用

1. 在 HWiNFO64 的“完整模式”中打开“主板 → Intel ME”，确认 `Boot Guard Verified Boot Policy` 为“禁用”。
2. 将 BIOS 文件拖拽到 `14th_b0_cep_patcher.py` 上。不添加参数时默认执行修改，输出文件写入原 BIOS 文件所在目录。
3. 七彩虹主板可使用 BIOS 内刷入；铭瑄、精粤、昂达主板使用官方 UEFI FPT 刷入。

## 文件组成

| 文件或目录 | 用途 |
|---|---|
| [`14th_b0_cep_patcher.py`](14th_b0_cep_patcher.py) | 主程序，执行 BIOS 定位、补丁和最终回读校验 |
| [`14th_b0_cep_checker.py`](14th_b0_cep_checker.py) | 安全回归检查器，验证定位、ABI、checksum 和 fail-closed 逻辑 |
| [`requirements.txt`](requirements.txt) | 固定 Capstone 和 uefi_firmware Python 依赖 |
| [`tools/`](tools/) | 随工具集提供的外部 EXE |

主程序：[`14th_b0_cep_patcher.py`](14th_b0_cep_patcher.py)

该工具在 UEFI BIOS 中定位 CEP 相关策略路径，通过 pCode mailbox 固定写入：

```text
command     = 0x901
sub-command = 1
data        = 3
```

其中 `data=3` 表示同时请求关闭：

```text
bit0 = IA CEP
bit1 = GT CEP
```

该命令语义不是所有 CPU、stepping、微码和固件都通用。工具只负责结构定位、
等长改写和静态校验，不能替代实机兼容性验证。

## 处理范围

工具分两个阶段处理固件：

| 阶段 | 模块 | 行为 |
|---|---|---|
| FSP-M | `SiInitPreMemFsp` | 必须找到唯一策略块，替换成固定 `0x901/1 data=3` 盲写 |
| FSP-S | `SiInitFsp` | 只有发现原生 `0x801/0x901` 配对路径时才强制改写为关闭 |

FSP-S 的处理规则：

- `SiInitFsp` 不存在：报告 `skipped`。
- 没有 `0x801` 或没有 `0x901`：报告 `skipped`。
- 两个签名都存在，但没有任何唯一、可安全解析的路径：停止，不生成输出。
- 找到多个候选路径：停止，不猜测。
- 找到唯一路径：删除门控检查，强制调用该模块已有的 mailbox helper。

该设计保证 FSP-S 不会在没有原厂支撑路径时凭空注入代码。

## 核心特性

- 不使用 SHA256 白名单或 BIOS 版本偏移表。
- 源文件 SHA256 只用于报告追踪，不参与定位。
- 使用 UEFIExtract 解包模块，并通过 GUID、模块边界和映像切片验证定位。
- FSP-M 使用固定分支特征、Epilogue 和模块内映射定位替换块。
- 使用带栈状态的有界控制流分析证明 `[ebp-4]` 是局部变量槽。
- 从原厂 `0x137/1` 调用动态解析 mailbox helper。
- 验证 helper 的参数 ABI、所有可达返回路径和调用方栈清理方式。
- FSP-S 使用 PE32 可执行节、函数 Prologue、`0x801/0x901`、父路径门控和
  helper 返回路径进行多重锚定。
- 支持未压缩 FSP-S 和 EFI 1.1 压缩的 FSP-S。
- 压缩 FSP-S 重新压缩后必须恢复原始压缩流长度。
- 支持 FFS Header 和 Header2，并验证 Header/File checksum。
- 输出完整 ROM、FSP-M FFS、可选的 FSP-S PE 和 JSON 审计报告。
- 补丁后重新解包，验证模块位置、大小和补丁内容。

## 环境要求

- Python 3.10 或更高版本。
- [Capstone](https://www.capstone-engine.org/)。
- UEFIExtract。
- 处理 EFI 1.1 压缩 FSP-S 时需要 `uefi_firmware` 的 `efi_compressor`。

安装 Python 依赖：

```powershell
python -m pip install -r requirements.txt
```

默认 UEFIExtract 路径：

```text
tools\UEFIExtract.exe
```

工具当前锁定并验证过的解析器版本：

```text
NE alpha 75 (Jul 10 2026)
```

其他版本默认拒绝运行。只有确认 `info.txt` 和目录结构仍兼容后，才应使用：

```powershell
--allow-uefiextract-version
```

覆盖状态会写入 JSON 报告。

## 使用方法

以下命令均在仓库根目录执行。

### 仅分析

```powershell
python 14th_b0_cep_patcher.py `
  .\original.rom `
  --dry-run
```

Dry-run 会完成：

- UEFIExtract 解包
- FSP-M 结构分析
- FSP-S 检测和可能的压缩重打包
- payload、差异范围和反汇编检查

Dry-run 不写文件，也不执行最终的补丁后重新解包验证。

### 正式生成

推荐显式指定输出路径：

```powershell
python 14th_b0_cep_patcher.py `
  .\original.rom `
  --output .\patched.rom
```

覆盖已有输出：

```powershell
python 14th_b0_cep_patcher.py .\original.rom --output .\patched.rom --force
```

### 命令行参数

| 参数 | 说明 |
|---|---|
| `input` | 原始完整 BIOS/ROM 文件 |
| `--output PATH` | 补丁后 ROM 路径 |
| `--report PATH` | JSON 报告路径 |
| `--uefiextract PATH` | 指定 `UEFIExtract.exe` |
| `--dry-run` | 只分析和打印结果，不写文件 |
| `--force` | 覆盖已有输出 |
| `--allow-uefiextract-version` | 允许非锁定版本的 UEFIExtract |

未指定 `--output` 时：

- 输出文件写入输入 BIOS 所在目录。
- 文件名由原文件名追加 `_IA_GT_CEP_OFF`。

## 输出文件

正式运行可能生成：

```text
<stem>_IA_GT_CEP_OFF<原扩展名>
SiInitPreMemFsp_<profile>_IA_GT_CEP_OFF.ffs
SiInitFsp_<profile>_IA_GT_CEP_OFF.pe32
<输出文件名>.report.json
```

其中 `SiInitFsp_*.pe32` 只在 FSP-S 实际打补丁时生成。

## 校验内容

工具在写出文件前执行：

1. 输入和输出长度一致。
2. 所有差异只能位于：
   - FSP-M 替换块；
   - FSP-S 重压缩流或 PE 替换范围；
   - 必要时的 FFS File checksum 字节。
3. 从原始 ROM 重建的补丁结果必须逐字节等于输出。
4. 新 payload 的反汇编必须调回原厂 helper。
5. FSP-M payload 必须清理四个参数并返回 0。
6. FSP-S payload 必须使用原 helper、两个栈参数和原函数 Epilogue。
7. FFS Header/File checksum 必须有效。
8. 补丁后重新 UEFIExtract：
   - 模块 base 和 size 不变；
   - FSP-M TE 映射不变；
   - 替换块逐字节一致；
   - FSP-S PE 逐字节一致。

任一检查失败都会中止，不写出补丁文件。

## JSON 报告

报告主要包含：

- 输入 SHA256。
- UEFIExtract 版本和版本覆盖状态。
- 目标模块 GUID、base、size 和映像路径。
- FSP-M TE/ROM 替换块、Epilogue、函数入口和 helper。
- FSP-M helper 参数、返回路径和最大栈参数偏移。
- FSP-M payload、新 call rel32 和完整反汇编。
- FSP-S `patched` 或 `skipped`、原因及全部结构定位点。
- FSP-S PE 和压缩流 SHA256/大小。
- 压缩平衡填充长度。
- 允许修改范围、总差异数和非预期差异数。
- FFS checksum 和补丁后重新解包结果。

PowerShell 读取 UTF-8 报告时建议显式指定编码：

```powershell
Get-Content .\patch.report.json -Raw -Encoding UTF8 |
  ConvertFrom-Json
```

## Checker 与测试

`14th_b0_cep_checker.py` 是独立的单元检查脚本。它不会处理 BIOS，
而是验证 patcher 的关键安全逻辑：

```powershell
14th_b0_cep_checker.py
```

静态检查：

```powershell
python -m ruff format --check14th_b0_cep_patcher.py
python -m ruff check 14th_b0_cep_patcher.py
python -m py_compile 14th_b0_cep_patcher.py
```

当前测试覆盖：

- FFS Header/Header2
- FFS File checksum
- 模块内 TE 映射
- 可执行节属性
- 栈帧控制流
- 四参数 mailbox ABI
- helper 多返回路径
- FSP-S `0x801/0x901` 配对检测
- FSP-S 单签名跳过
- FSP-S 无效门控 fail-closed
- FSP-S 保留指令位置

## 注意事项

- 修改 ROM 会改变厂商镜像签名，FFS checksum 有效也不能恢复该签名；Secure Flash 可能拒绝刷入。
- 刷写前保留完整 BIOS/SPI 备份，并准备 FPT 或 SPI 编程器作为恢复手段。
- `0x901/1 data=3` 与平台相关，使用前应确认目标 CPU、微码和 BIOS 的行为。
