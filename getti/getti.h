#pragma once

#include <Windows.h>

void GetAdmin(LPWSTR szCmdLine = nullptr);
void GetSystem(LPWSTR szCmdLine = nullptr);
void GetTrustedInstaller(BOOL szCmdLine = FALSE, LPWSTR params = nullptr);