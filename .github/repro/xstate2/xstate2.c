// Kernel exception CONTEXT size on this host: hardware fault vs software
// RaiseException, before and after EnableProcessOptionalXStateFeatures(AMX).
#include <windows.h>
#include <stdio.h>

typedef BOOL (WINAPI *PENABLE)(DWORD64);
typedef BOOL (WINAPI *PGETTHREAD)(HANDLE, PDWORD64);

struct ctxex { LONG off; DWORD len; };
static volatile DWORD g_flags, g_all, g_xstate;

static LONG CALLBACK veh(PEXCEPTION_POINTERS ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code != 0xE0000001 && code != EXCEPTION_ACCESS_VIOLATION) return EXCEPTION_CONTINUE_SEARCH;
    CONTEXT *c = ep->ContextRecord;
    struct ctxex *ex = (struct ctxex *)((char *)c + sizeof(CONTEXT)); // All, Legacy, XState
    g_flags = c->ContextFlags; g_all = ex[0].len; g_xstate = ex[2].len;
    if (code == EXCEPTION_ACCESS_VIOLATION) c->Rip += 2; // skip the 2-byte "movb (%rax),%al"
    return EXCEPTION_CONTINUE_EXECUTION;
}

static void hwfault(void) {
    __asm__ volatile("movq $0x1000, %%rax\n\tmovb (%%rax), %%al\n\t" ::: "rax", "memory");
}

static void measure(const char *tag) {
    HMODULE k = GetModuleHandleA("kernel32");
    DWORD n = 0; PCONTEXT pc = NULL;
    InitializeContext(NULL, 0x10005f /* CONTEXT_ALL|CONTEXT_XSTATE */, &pc, &n);
    DWORD64 tm = 0; PGETTHREAD gt = (PGETTHREAD)GetProcAddress(k, "GetThreadEnabledXStateFeatures");
    BOOL gtok = gt ? gt(GetCurrentThread(), &tm) : FALSE;
    g_flags = g_all = g_xstate = 0;
    hwfault();
    DWORD hf = g_flags, ha = g_all, hx = g_xstate;
    g_flags = g_all = g_xstate = 0;
    RaiseException(0xE0000001, 0, 0, NULL);
    printf("%s: system=0x%llx thread=%s0x%llx InitializeContext=%lu | HW fault: flags=0x%lx All=%lu XState=%lu | RaiseException: flags=0x%lx All=%lu XState=%lu\n",
           tag, (unsigned long long)GetEnabledXStateFeatures(), gtok ? "" : "(n/a)", (unsigned long long)tm, n,
           hf, ha, hx, g_flags, g_all, g_xstate);
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
