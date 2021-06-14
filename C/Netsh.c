// PortProxy PoC
// @TheXC3LL
//https://adepts.of0x.cc/netsh-portproxy-code/

#include <Windows.h>
#include <stdio.h>


DWORD iphlpsvcUpdate(void) {
	SC_HANDLE hManager;
	SC_HANDLE hService;
	SERVICE_STATUS serviceStatus;
	DWORD retStatus = 0;
	DWORD ret = -1;

	hManager = OpenSCManagerA(NULL, NULL, GENERIC_READ);
	if (hManager) {
		hService = OpenServiceA(hManager, "IpHlpSvc", SERVICE_PAUSE_CONTINUE | SERVICE_QUERY_STATUS);
		if (hService) {
			printf("[*] Connected to IpHlpSvc\n");
			retStatus = ControlService(hService, SERVICE_CONTROL_PARAMCHANGE, &serviceStatus);
			if (retStatus) {
				printf("[*] Configuration update requested\n");
				ret = 0;
			}
			else {
				printf("[!] ControlService() failed!\n");
			}
			CloseServiceHandle(hService);
			CloseServiceHandle(hManager);
			return ret;
		}
		CloseServiceHandle(hManager);
		printf("[!] OpenServiceA() failed!\n");
		return ret;
	}
	printf("[!] OpenSCManager() failed!\n");
	return ret;
}

DWORD addEntry(LPSTR source, LPSTR destination) {
	LPCSTR v4tov4 = "SYSTEM\\ControlSet001\\Services\\PortProxy\\v4tov4\\tcp";
	HKEY hKey = NULL;
	LSTATUS retStatus = 0;
	DWORD ret = -1;
	
	retStatus = RegCreateKeyExA(HKEY_LOCAL_MACHINE, v4tov4, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
	if (retStatus == ERROR_SUCCESS) {
		retStatus = (RegSetValueExA(hKey, source, 0, REG_SZ, (LPBYTE)destination, strlen(destination) + 1));
		if (retStatus == ERROR_SUCCESS) {
			printf("[*] New entry added\n");
			ret = 0;
		}
		else {
			printf("[!] RegSetValueExA() failed!\n");
		}
		RegCloseKey(hKey);
		return ret;
	}
	printf("[!] RegCreateKeyExA() failed!\n");
	return ret;
}

DWORD deleteEntry(LPSTR source) {
	LPCSTR v4tov4 = "SYSTEM\\ControlSet001\\Services\\PortProxy\\v4tov4\\tcp";
	HKEY hKey = NULL;
	LSTATUS retStatus = 0;
	DWORD ret = -1;

	retStatus = RegCreateKeyExA(HKEY_LOCAL_MACHINE, v4tov4, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
	if (retStatus == ERROR_SUCCESS) {
		retStatus = RegDeleteKeyValueA(HKEY_LOCAL_MACHINE, v4tov4, source);
		if (retStatus == ERROR_SUCCESS) {
			printf("[*] New entry deleted\n");
			ret = 0;
		}
		else {
			printf("[!] RegDeleteKeyValueA() failed!\n");
		}
		RegCloseKey(hKey);
		return ret;
	}
	printf("[!] RegCreateKeyExA() failed!\n");
	return ret;
}

int main(int argc, char** argv) {
	printf("\t\t-=<[ PortProxy PoC by @TheXC3LL ]>=-\n\n");
	if (argc <= 2) {
		printf("[!] Invalid syntax! Usage: PortProxy.exe SOURCE_IP/PORT DESTINATION_IP/PORT (example: ./PortProxy.exe 0.0.0.0/1337 10.0.2.2/22\n");
	}
	if (addEntry(argv[1], argv[2]) != -1) {
		if (iphlpsvcUpdate() == -1) {
			printf("[!] Something went wrong :S\n");
		}
		if (deleteEntry(argv[1]) == -1) {
				printf("[!] Troubles deleting the entry, please try it manually!!\n");
		}
	}
	return 0;
}
