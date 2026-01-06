#include "resource.h"
#include "getti.h"
#include <shellscalingapi.h>
#pragma comment(lib, "Shcore.lib")
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
    processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")



INT_PTR CALLBACK DlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_INITDIALOG:
        SetWindowPos(hwndDlg, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        return TRUE;
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK:
        case IDCANCEL:
            EndDialog(hwndDlg, LOWORD(wParam));
            return TRUE;
        }
        break;
    }
    return FALSE;
}

int WINAPI WinMain(
    _In_        HINSTANCE hInstance,
    _In_opt_    HINSTANCE hPrevInstance,
    _In_        LPSTR     lpCmdLine,
    _In_        int       nCmdShow
) {
    GetTrustedInstaller(TRUE);
    
    SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);
    DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, DlgProc);

    return 0;

}