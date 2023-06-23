#include <Windows.h>

using MsgBoxFunc = NTSTATUS(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);


int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    HMODULE user32dll = LoadLibraryA("user32.dll");
    MsgBoxFunc messeageBoxA = (MsgBoxFunc)GetProcAddress(user32dll, "MessageBoxA");
    messeageBoxA(NULL, "Hello from process hollowing", "Hello", MB_OK);
    return 1;
}