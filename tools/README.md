# Bundled Tools

该目录保存运行和人工复核 BIOS 补丁所需的外部程序。

| 文件 | 用途 |
|---|---|
| `UEFIExtract.exe` | 自动补丁流程解析 UEFI 固件，必需 |
| `UEFITool.exe` | 人工查看 FFS、FV、Section 和固件结构 |
| `ifrextractor.exe` | 提取 BIOS Setup IFR，用于分析选项和默认值 |
| `DL_SCEWIN.exe` | Intel 微码、签名和固件分析辅助工具 |

`14th_b0_cep_patcher.py` 默认调用：

```text
tools/UEFIExtract.exe
```

Python 依赖不在此目录复制：

```text
capstone==5.0.9
uefi_firmware==1.16
```

它们仍通过 Python/pip 环境安装：

```powershell
python -m pip install -r bios\00_Tools\requirements.txt
```

这些 EXE 的版权和再分发条件归各自原作者所有。对外分发整套工具前，应分别确认对应许可证。
