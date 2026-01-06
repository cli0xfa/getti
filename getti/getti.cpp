#include "getti.h"
#include <sddl.h>
#include <tlhelp32.h>
#include <vector>
#include <string>

static void EnablePrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    LUID luid;
    LookupPrivilegeValue(NULL, lpszPrivilege, &luid);
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
}

static void EnableAllPrivileges(HANDLE hToken, BOOL bEnable) {
    std::vector<std::wstring> lpAllPrivilege = {
        SE_INCREASE_QUOTA_NAME,						// 为进程调整内存配额
        SE_SECURITY_NAME,							// 管理审核和安全日志
        SE_TAKE_OWNERSHIP_NAME,						// 取得文件或其他对象的所有权
        SE_LOAD_DRIVER_NAME,						// 加载和卸载设备驱动程序
        SE_SYSTEM_PROFILE_NAME,						// 配置文件系统性能
        SE_SYSTEMTIME_NAME,							// 更改系统时间
        SE_PROF_SINGLE_PROCESS_NAME,				// 配置文件单一进程
        SE_INC_BASE_PRIORITY_NAME,					// 提高计划优先级
        SE_CREATE_PAGEFILE_NAME,					// 创建一个页面文件
        SE_BACKUP_NAME,								// 备份文件和目录
        SE_RESTORE_NAME,							// 还原文件和目录
        SE_SHUTDOWN_NAME,							// 关闭系统
        SE_DEBUG_NAME,								// 调试程序
        SE_SYSTEM_ENVIRONMENT_NAME,					// 修改固件环境值
        SE_CHANGE_NOTIFY_NAME,						// 绕过遍历检查
        SE_REMOTE_SHUTDOWN_NAME,					// 从远程系统强制关机
        SE_UNDOCK_NAME,								// 从扩展坞上取下计算机
        SE_MANAGE_VOLUME_NAME,						// 执行卷维护任务
        SE_IMPERSONATE_NAME,						// 身份验证后模拟客户端
        SE_CREATE_GLOBAL_NAME,						// 创建全局对象
        SE_INC_WORKING_SET_NAME,					// 增加进程工作集
        SE_TIME_ZONE_NAME,							// 更改时区
        SE_CREATE_SYMBOLIC_LINK_NAME,				// 创建符号链接
        SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME	// 获取同一会话中另一个用户的模拟令牌
        SE_SYNC_AGENT_NAME,                         // 充当同步代理
        SE_CREATE_PERMANENT_NAME,                   // 创建永久对象
        SE_TCB_NAME,                                // 充当操作系统的一部分
        SE_CREATE_TOKEN_NAME,                       // 创建令牌对象
        SE_ASSIGNPRIMARYTOKEN_NAME,                 // 替换进程级令牌
        SE_LOCK_MEMORY_NAME,                        // 在内存中锁定页
        SE_MACHINE_ACCOUNT_NAME,                    // 将工作站添加到域
        SE_AUDIT_NAME,                              // 生成安全性审核
        SE_TRUSTED_CREDMAN_ACCESS_NAME,             // 作为受信任的呼叫方访问凭据管理器
        SE_RELABEL_NAME,                            // 修改对象标签
        SE_ENABLE_DELEGATION_NAME                   // 启用要信任的用于委派的计算机和用户帐户
    };
    for (const auto& privilege : lpAllPrivilege) {
        EnablePrivilege(hToken, privilege.c_str(), bEnable);
    }
}

static bool IsSystem() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        return false;
    }
    BOOL isSystem = FALSE;
    DWORD tokenInfoSize = 0;
    PTOKEN_USER pTokenUser = NULL;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &tokenInfoSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return FALSE;
    }
    pTokenUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, tokenInfoSize);
    if (!pTokenUser) {
        CloseHandle(hToken);
        return FALSE;
    }
    if (GetTokenInformation(hToken, TokenUser, pTokenUser, tokenInfoSize, &tokenInfoSize)) {
        LPSTR pStringSid = NULL;
        if (ConvertSidToStringSidA(pTokenUser->User.Sid, &pStringSid)) {
            if (strcmp(pStringSid, "S-1-5-18") == 0)
                isSystem = TRUE;
            LocalFree(pStringSid);
        }
    }
    if (pTokenUser) {
        HeapFree(GetProcessHeap(), 0, pTokenUser);
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return isSystem;
}

static bool IsTrustedInstaller() {
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        return false;
    }
    BOOL isTI = FALSE;
    DWORD tokenInfoSize = 0;
    PTOKEN_GROUPS pTokenGroups = NULL;
    GetTokenInformation(hToken, TokenGroups, NULL, 0, &tokenInfoSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return FALSE;
    }
    pTokenGroups = (PTOKEN_GROUPS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, tokenInfoSize);
    if (!pTokenGroups) {
        CloseHandle(hToken);
        return FALSE;
    }
    if (GetTokenInformation(hToken, TokenGroups, pTokenGroups, tokenInfoSize, &tokenInfoSize)) {
        for (DWORD i = 0; i < pTokenGroups->GroupCount; i++) {
            LPSTR pStringSid = NULL;
            if (ConvertSidToStringSidA(pTokenGroups->Groups[i].Sid, &pStringSid)) {
                if (strstr(pStringSid, "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464") != NULL) {
                    isTI = TRUE;
                    LocalFree(pStringSid);
                    break;
                }
                LocalFree(pStringSid);
            }
        }
    }
    if (pTokenGroups) {
        HeapFree(GetProcessHeap(), 0, pTokenGroups);
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return isTI;
}

static bool GetSystemToken(PHANDLE phToken) {
    HANDLE hSelfToken = NULL;
    OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hSelfToken);
    EnableAllPrivileges(hSelfToken, TRUE);
    BOOL bRet = TRUE;
    DWORD dwUserSessionId;
    ProcessIdToSessionId(GetCurrentProcessId(), &dwUserSessionId);
    PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    for (Process32First(hSnapshot, &pe32); Process32Next(hSnapshot, &pe32);) {
        if (_wcsicmp(pe32.szExeFile, L"winlogon.exe")) {
            continue;
        }
        HANDLE hProcess = OpenProcess(TOKEN_ALL_ACCESS, FALSE, pe32.th32ProcessID);

        HANDLE hToken = NULL;
        OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken);
        DWORD dwSessionId = 0;
        DWORD dwBufSize = 0;
        if (GetTokenInformation(hToken, TokenSessionId, &dwSessionId, sizeof(dwSessionId), &dwBufSize)) {
            if (dwSessionId != dwUserSessionId) {
                CloseHandle(hToken);
                CloseHandle(hProcess);
                continue;
            }
        }
        else {
            bRet = FALSE;
            CloseHandle(hToken);
            CloseHandle(hProcess);
            continue;
        }
        if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, phToken)) {
            bRet = FALSE;
        }
        CloseHandle(hToken);
        CloseHandle(hProcess);
        break;
    }
    CloseHandle(hSnapshot);
    return bRet;
}

static bool GetTrustedInstallerToken(PHANDLE phToken) {
    if (!phToken) return false;
    *phToken = NULL;

    SC_HANDLE hSC = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSC) return false;

    SC_HANDLE hSvc = OpenServiceW(hSC, L"TrustedInstaller",
        SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP);
    if (!hSvc) {
        CloseServiceHandle(hSC);
        return false;
    }

    SERVICE_STATUS ss{};
    if (!QueryServiceStatus(hSvc, &ss)) {
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSC);
        return false;
    }

    if (ss.dwCurrentState != SERVICE_RUNNING) {
        if (ss.dwCurrentState == SERVICE_STOPPED) {
            if (!StartServiceW(hSvc, 0, NULL)) {
                CloseServiceHandle(hSvc);
                CloseServiceHandle(hSC);
                return false;
            }
        }

        for (int i = 0; i < 60; ++i) {
            Sleep(ss.dwWaitHint ? ss.dwWaitHint : 500);
            if (!QueryServiceStatus(hSvc, &ss)) {
                CloseServiceHandle(hSvc);
                CloseServiceHandle(hSC);
                return false;
            }
            if (ss.dwCurrentState == SERVICE_RUNNING) break;
        }
        if (ss.dwCurrentState != SERVICE_RUNNING) {
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hSC);
            return false;
        }
    }

    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSC);
        return false;
    }

    PROCESSENTRY32W pe{ sizeof(pe) };
    for (BOOL b = Process32FirstW(hSnap, &pe); b; b = Process32NextW(hSnap, &pe)) {
        if (_wcsicmp(pe.szExeFile, L"TrustedInstaller.exe") == 0) {
            pid = pe.th32ProcessID;
            break;
        }
    }
    CloseHandle(hSnap);
    if (!pid) {
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSC);
        return false;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSC);
        return false;
    }

    HANDLE hTok = NULL;
    BOOL ok = OpenProcessToken(hProc, TOKEN_QUERY | TOKEN_DUPLICATE, &hTok);
    CloseHandle(hProc);
    if (!ok) {
        CloseServiceHandle(hSvc);
        CloseServiceHandle(hSC);
        return false;
    }

    HANDLE hDup = NULL;
    ok = DuplicateTokenEx(hTok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDup);
    CloseHandle(hTok);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSC);
    if (!ok) return false;

    *phToken = hDup;
    return true;
}

static bool EnableUIAccess(PHANDLE phToken) {
    DWORD uiAccess = TRUE;
    if (!SetTokenInformation(*phToken, TokenUIAccess, &uiAccess, sizeof(uiAccess)))
        return false;
    return true;
}

static bool StartProcessWithToken(HANDLE hToken, LPWSTR lpCommandLine) {
    HANDLE hPrimaryToken = NULL;
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken)) {
        return false;
    }
    EnableAllPrivileges(hPrimaryToken, TRUE);
    STARTUPINFOW si = { sizeof(STARTUPINFOW) };
    PROCESS_INFORMATION pi = { 0 };
    if (!CreateProcessWithTokenW(hPrimaryToken, LOGON_WITH_PROFILE, NULL, lpCommandLine, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        if (!CreateProcessAsUserW(hPrimaryToken, NULL, lpCommandLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
            return false;
        }
        else {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }
    else {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    return true;
}

void GetSystem() {
    if (!IsSystem()) {
        HANDLE hToken = NULL;
        if (GetSystemToken(&hToken)) {
            if (StartProcessWithToken(hToken, GetCommandLineW())) {
                CloseHandle(hToken);
                ExitProcess(0);
            }
            else {
                CloseHandle(hToken);
                MessageBox(NULL, L"Failed to start process with system token. Administrator privileges may be required", L"Error", MB_ICONERROR | MB_OK);
                ExitProcess(1);
            }
        }
        else {
            MessageBox(NULL, L"Failed to get system token.", L"Error", MB_ICONERROR | MB_OK);
            ExitProcess(1);
        }
    }
}

void GetTrustedInstaller(BOOL enableUIAccess) {
    GetSystem();
    if (!IsTrustedInstaller()) {
        HANDLE hToken = NULL;
        if (GetTrustedInstallerToken(&hToken)) {
            if (enableUIAccess) {
                EnableUIAccess(&hToken);
            }
            if (StartProcessWithToken(hToken, GetCommandLineW())) {
                CloseHandle(hToken);
                ExitProcess(0);
            }
            else {
                CloseHandle(hToken);
                MessageBox(NULL, L"Failed to start process with TrustedInstaller token.", L"Error", MB_ICONERROR | MB_OK);
                ExitProcess(1);
            }
        }
        else {
            MessageBox(NULL, L"Failed to get TrustedInstaller token.", L"Error", MB_ICONERROR | MB_OK);
            ExitProcess(1);
        }
    }
}