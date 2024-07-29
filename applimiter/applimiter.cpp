// applimiter.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>
#include <psapi.h>
#include <codecvt>
#include <iphlpapi.h>
#include <sstream>

#include "windivert.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MAXBUF 0xFFFF

std::string wstring_to_string(const std::wstring& wstr) {
    std::wstring_convert<std::codecvt_utf8<wchar_t>, wchar_t> converter;
    return converter.to_bytes(wstr);
}

std::wstring GetProcessPath(DWORD processID) {
    wchar_t path[MAX_PATH] = { 0 };
    HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
    if (process) {
        if (GetModuleFileNameExW(process, NULL, path, MAX_PATH) == 0) {
            CloseHandle(process);
        }
        CloseHandle(process);
    }
    return std::wstring(path);
}

DWORD GetProcessIdFromConnection(WINDIVERT_IPHDR* ipHeader, WINDIVERT_TCPHDR* tcpHeader, const std::string& serverIp, int serverPort) {
    PMIB_TCPTABLE_OWNER_PID tcpTable;
    DWORD size = 0;
    DWORD processId = 0;

    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    tcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(size);

    if (GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            MIB_TCPROW_OWNER_PID row = tcpTable->table[i];

            // Compare the IP addresses and ports
            if (row.dwLocalAddr == ipHeader->SrcAddr && row.dwLocalPort == tcpHeader->SrcPort &&
                row.dwRemoteAddr == ipHeader->DstAddr && row.dwRemotePort == tcpHeader->DstPort) {
                processId = row.dwOwningPid;
                break;
            }
        }
    }
    free(tcpTable);
    return processId;
}

bool wstringContainsSubstring(const std::wstring& wstr, const std::string& substr) {
    // Convert wstring to string
    std::string str(wstr.begin(), wstr.end());

    // Perform substring search
    return (str.find(substr) != std::string::npos);
}

void printUsage() {
    std::cout << "Usage: applimiter.exe <serverIp> <serverPort>" << std::endl;
}

int main(int argc, char* argv[])
{
    if (argc != 3) {
        printUsage();
        return 1;
    }

    std::string serverIp = argv[1];
    int serverPort;
    std::istringstream(argv[2]) >> serverPort;

    if (serverPort <= 0 || serverPort > 65535) {
        std::cerr << "Error: Invalid port number. Port must be between 1 and 65535." << std::endl;
        return 1;
    }

    std::string allowedApp = "navicat.exe";

    // Open WinDivert handle for TCP packets to the specified server and port
    std::string filter = "outbound && ip.DstAddr == " + serverIp + " && tcp.DstPort == " + std::to_string(serverPort);
    HANDLE handle = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "Error: Unable to open WinDivert handle. Error type: " << GetLastError() << std::endl;
        return 1;
    }

    WINDIVERT_ADDRESS addr;
    char packet[MAXBUF];
    UINT packetLen;
    PWINDIVERT_IPHDR ipHeader;
    PWINDIVERT_TCPHDR tcpHeader;

    std::cout << "Listening to check all traffic..." << std::endl;

    while (true) {
        // Receive packets
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLen, &addr)) {
            std::cerr << "Warning: Failed to read packet." << std::endl;
            continue;
        }

        // Parse packet headers
        WinDivertHelperParsePacket(packet, packetLen, &ipHeader, NULL, NULL, NULL, NULL, &tcpHeader, NULL, NULL, NULL, NULL, NULL);

        // Get the process ID from the TCP connection
        DWORD processId = GetProcessIdFromConnection(ipHeader, tcpHeader, serverIp, serverPort);

        std::wstring processPath = GetProcessPath(processId);

        // Check if the packet is from the allowed application
        if (wstringContainsSubstring(processPath, allowedApp)) {
            // Allow packet
            UINT sendlen;
            if (!WinDivertSend(handle, packet, packetLen, &sendlen, &addr)) {
                std::cerr << "Warning: Failed to reinject packet." << std::endl;
            }
        }
        else {
            // Block packet
            const std::string processPathStr = wstring_to_string(processPath);
            if (processPathStr.length() > 0)
                std::cout << "Blocked packet from: " << processPathStr << std::endl;
        }
    }

    WinDivertClose(handle);
    return 0;
}
