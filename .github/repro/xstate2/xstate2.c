// Does the kernel's exception CONTEXT grow after a process opts into AMX?
// Measures InitializeContext and the frame a vectored handler is handed,
// before and after EnableProcessOptionalXStateFeatures(AMX).
#include <windows.h>
#include <stdio.h>

typedef BOOL (WINAPI *PENABLE)(DWORD64);
typedef BOOL (WINAPI *PGETTHREAD)(HANDLE, PDWORD64);
typedef BOOL (WINAPI *PINIT2)(PVOID, DWORD, PCONTEXT *, PDWORD, ULONG64);

struct ctxex { LONG off; DWORD len; };
static volatile DWORD g_flags, g_all, g_xstate;

static LONG CALLBACK veh(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != 0xE0000001) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT *c = ep->ContextRecord;
    struct ctxex *ex = (struct ctxex *)((char *)c + sizeof(CONTEXT)); // All, Legacy, XState
    g_flags = c->ContextFlags; g_all = ex[0].len; g_xstate = ex[2].len;
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void measure(const char *tag) {
    HMODULE k = GetModuleHandleA("kernel32");
    DWORD n = 0; PCONTEXT pc = NULL;
    InitializeContext(NULL, 0x10005f /* CONTEXT_ALL|CONTEXT_XSTATE */, &pc, &n);
    DWORD n2 = 0; PINIT2 init2 = (PINIT2)GetProcAddress(k, "InitializeContext2");
    if (init2) init2(NULL, 0x10005f, &pc, &n2, 0);
    DWORD64 tm = 0; PGETTHREAD gt = (PGETTHREAD)GetProcAddress(k, "GetThreadEnabledXStateFeatures");
    BOOL gtok = gt ? gt(GetCurrentThread(), &tm) : FALSE;
    g_flags = g_all = g_xstate = 0;
    RaiseException(0xE0000001, 0, 0, NULL);
    printf("%s: system=0x%llx thread=%s0x%llx InitializeContext=%lu InitializeContext2=%lu VEH: flags=0x%lx All.Length=%lu XState.Length=%lu\n",
           tag, (unsigned long long)GetEnabledXStateFeatures(), gtok ? "" : "(n/a)", (unsigned long long)tm, n, n2, g_flags, g_all, g_xstate);
}

int main(void) {
    AddVectoredExceptionHandler(1, veh);
    measure("before");
    PENABLE en = (PENABLE)GetProcAddress(GetModuleHandleA("kernel32"), "EnableProcessOptionalXStateFeatures");
    if (!en) { printf("EnableProcessOptionalXStateFeatures: unavailable\n"); return 0; }
    BOOL ok = en((1ull << 17) | (1ull << 18)); // XTILECFG | XTILEDATA
    printf("EnableProcessOptionalXStateFeatures(AMX) = %d (err %lu)\n", ok, ok ? 0 : GetLastError());
    measure("after");
    return 0;
}
