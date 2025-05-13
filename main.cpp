#include <windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>
#include <psapi.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

class AntiDebugController {
public:
    void runAllChecks() {
        bool detected = false;
        std::string reason;

        if (checkIsDebuggerPresent()) { detected = true; reason = "IsDebuggerPresent"; }
        else if (checkRemoteDebugger()) { detected = true; reason = "CheckRemoteDebuggerPresent"; }
        else if (checkNtQuery()) { detected = true; reason = "NtQueryInformationProcess - DebugFlags"; }
        else if (checkTiming()) { detected = true; reason = "QueryPerformanceCounter"; }
        else if (checkPEB()) { detected = true; reason = "PEB.BeingDebugged"; }
        else if (checkHWBP()) { detected = true; reason = "Hardware Breakpoints"; }
        else if (checkVEH()) { detected = true; reason = "VEH Handler Hook"; }
        else if (checkIATHook("kernel32.dll", "WriteProcessMemory")) { detected = true; reason = "IAT Hook Detected"; }
        else if (checkSuspiciousModules()) { detected = true; reason = "Suspicious DLL Loaded"; }

        if (detected) {
            logDetection(reason);
            handleDetection(reason.c_str());
        }
    }

private:
    void handleDetection(const char* method) {
        std::cout << "[!] 디버거 감지됨! 종료함. (" << method << ")\n";
        MessageBoxA(NULL, method, "안티디버깅", MB_ICONERROR);
        ExitProcess(0);
    }

    void logDetection(const std::string& reason) {
        FILE* f = fopen("antidebug_log.txt", "a");
        if (f) {
            SYSTEMTIME st;
            GetLocalTime(&st);
            fprintf(f, "[%04d-%02d-%02d %02d:%02d:%02d] DETECTED: %s\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
                reason.c_str());
            fclose(f);
        }
    }

    bool checkIsDebuggerPresent() {
        return IsDebuggerPresent();
    }

    bool checkRemoteDebugger() {
        BOOL debuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
        return debuggerPresent;
    }

    bool checkNtQuery() {
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;

        typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
            HANDLE, ULONG, PVOID, ULONG, PULONG);

        pNtQueryInformationProcess NtQueryInformationProcess =
            (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (!NtQueryInformationProcess) return false;

        DWORD debugFlags = 0;
        NTSTATUS status = NtQueryInformationProcess(
            GetCurrentProcess(), 0x1F, &debugFlags, sizeof(debugFlags), nullptr);

        return (NT_SUCCESS(status) && debugFlags == FALSE);
    }

    bool checkTiming() {
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);

        volatile int dummy = 0;
        for (int i = 0; i < 1000000; ++i) dummy += i;

        QueryPerformanceCounter(&end);
        double elapsedMs = ((end.QuadPart - start.QuadPart) * 1000.0) / freq.QuadPart;
        std::cout << "[*] 타이밍 체크: " << elapsedMs << "ms 소요됨\n";

        return elapsedMs > 100;
    }

    bool checkPEB() {
    #ifdef _M_X64
        BYTE* peb = (BYTE*)__readgsqword(0x60);
    #else
        BYTE* peb = (BYTE*)__readfsdword(0x30);
    #endif
        return peb[2];
    }

    bool checkHWBP() {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        HANDLE hThread = GetCurrentThread();
        if (GetThreadContext(hThread, &ctx)) {
            return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
        }
        return false;
    }

    bool checkVEH() {
        void* originalHandler = SetUnhandledExceptionFilter(NULL);
        SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)originalHandler);
        return originalHandler != NULL;
    }

    bool checkIATHook(const char* moduleName, const char* functionName) {
        FARPROC func = GetProcAddress(GetModuleHandleA(moduleName), functionName);
        if (!func) return false;
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(func, &mbi, sizeof(mbi))) {
            if (!(mbi.Protect & PAGE_EXECUTE_READ)) {
                return true;
            }
        }
        return false;
    }

    bool checkSuspiciousModules() {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        HANDLE hProcess = GetCurrentProcess();

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH];
                if (GetModuleFileNameA(hMods[i], szModName, sizeof(szModName) / sizeof(char))) {
                    std::string modName(szModName);
                    if (modName.find("cheat") != std::string::npos ||
                        modName.find("inject") != std::string::npos ||
                        modName.find("dbg") != std::string::npos) {
                        return true;
                    }
                }
            }
        }
        return false;
    }
};

int main() {
    std::cout << "[*] Anti-Debugging 시작...\n";
    AntiDebugController adc;
    adc.runAllChecks();
    std::cout << "[+] 디버거 없음. 정상 실행됨.\n";
    system("pause");
    return 0;
} // 커널모드 방어는 별도 드라이버(.sys)에서 구현함. 
// 커널모드 방어 기능: OpenProcess 차단, VAD 스캔, ObRegisterCallbacks, PsSetCreateProcessNotifyRoutineEx 등

