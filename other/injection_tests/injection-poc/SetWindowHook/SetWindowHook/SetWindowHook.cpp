#include <iostream>
#include <Windows.h>

int main()
{
	HMODULE library = LoadLibraryA("dllhook.dll");
	HOOKPROC hookProc = (HOOKPROC)GetProcAddress(library, "spotlessExport");

	HHOOK hook = SetWindowsHookEx(WH_KEYBOARD, hookProc, library, 0);
	Sleep(10 * 1000);
	UnhookWindowsHookEx(hook);

	return 0;
}