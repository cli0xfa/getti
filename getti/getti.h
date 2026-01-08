#pragma once

#include <Windows.h>

void GetAdmin(LPWSTR params = nullptr);
void GetSystem(LPWSTR params = nullptr);
void GetTrustedInstaller(BOOL enableUIAccess = FALSE, LPWSTR params = nullptr);