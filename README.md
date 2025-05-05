# Anti-Debug Controller for Anticheat_MoB

전장의 디배자 안티치트 개발 중 일부로, 
간단한 유저모드 기반 안티디버깅 탐지 프로그램입니다.  
디버거(Cheat Engine, x64dbg, Frida 등)가 프로세스에 붙어 있는지 다양한 방식으로 탐지합니다.

## 탐지 기법

- `IsDebuggerPresent`
- `CheckRemoteDebuggerPresent`
- `NtQueryInformationProcess (DebugFlags)`
- 타이밍 기반 분석 (`QueryPerformanceCounter`)
- `PEB.BeingDebugged` 직접 확인
- 하드웨어 브레이크포인트 사용 감지 (`Dr0~Dr3`)
- VEH 핸들러 훅 탐지
  + 클래스로 구조화하는 단계에서 TLS Callback 기능이 생략되었습니다. 추후 추가가 필요합니다. 

## 로그 기록

디버깅이 감지되면 `antidebug_log.txt` 파일에 이유와 시간이 기록됩니다.

## 빌드 방법 (Windows)

Visual Studio 또는 `g++`로 컴파일 가능:
```bash
g++ main.cpp -o AntiDebug.exe
```
