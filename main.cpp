#include "CertificateCloneTool.h"
#include <iostream>
#include <string>
#include <windows.h>

void DisplayCertificateInfo(const CertificateCloneTool::CertificateInfo& certInfo) {
    std::wcout << L"\nCertificate Information:\n";
    std::wcout << L"Subject: " << certInfo.subjectName << L"\n";
    std::wcout << L"Issuer: " << certInfo.issuerName << L"\n";
    std::wcout << L"Serial Number: " << certInfo.serialNumber << L"\n";
    std::wcout << L"Thumbprint: " << certInfo.thumbprint << L"\n";
    std::wcout << L"Certificate Size: " << certInfo.certificateData.size() << L" bytes\n";
    std::wcout << L"Signature Size: " << certInfo.signatureSize << L" bytes\n";
    std::wcout << L"PE Checksum: 0x" << std::hex << certInfo.checksum << std::dec << L"\n";
    std::wcout << L"Status: " << (certInfo.isValid ? L"Valid" : L"Invalid") << L"\n\n";
}

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8);

    CertificateCloneTool tool;
    std::wstring sourceFile;

    if (argc >= 2) {
        sourceFile = argv[1];
    } else {
        std::wcout << L"Drag and drop a signed file onto this executable\n";
        std::wcout << L"Or run: certclone.exe <signed_file>\n\n";
        std::wcout << L"Press Enter to exit...";
        std::wcin.get();
        return 1;
    }

    std::wcout << L"Certificate Clone Tool\n";
    std::wcout << L"Source (signed): " << sourceFile << L"\n";
    std::wcout << L"Source SHA256: " << tool.GetFileHash(sourceFile) << L"\n";

    CertificateCloneTool::CertificateInfo certInfo;
    if (!tool.ExtractCertificate(sourceFile, certInfo)) {
        std::wcerr << L"\nFailed to extract certificate from source file\n";
        std::wcout << L"\nPress Enter to exit...";
        std::wcin.get();
        return 1;
    }

    DisplayCertificateInfo(certInfo);

    std::wstring targetFile;
    std::wcout << L"Enter path to unsigned file to sign:\n> ";
    std::getline(std::wcin, targetFile);

    if (targetFile.size() >= 2 && targetFile.front() == L'"' && targetFile.back() == L'"') {
        targetFile = targetFile.substr(1, targetFile.size() - 2);
    }

    if (targetFile.empty()) {
        std::wcerr << L"\nNo target file specified\n";
        std::wcout << L"\nPress Enter to exit...";
        std::wcin.get();
        return 1;
    }

    std::wcout << L"\nApplying certificate to: " << targetFile << L"\n";

    if (!tool.ApplyCertificate(targetFile, certInfo)) {
        std::wcerr << L"Failed to apply certificate\n";
        std::wcout << L"\nPress Enter to exit...";
        std::wcin.get();
        return 1;
    }

    std::wcout << L"Certificate applied successfully\n";
    std::wcout << L"Target SHA256: " << tool.GetFileHash(targetFile) << L"\n";

    std::wstring status;
    if (tool.VerifyCertificate(targetFile, status)) {
        std::wcout << L"Verification: " << status << L"\n";
    } else {
        std::wcout << L"Verification note: " << status << L"\n";
    }

    std::wcout << L"\nPress Enter to exit...";
    std::wcin.get();
    return 0;
}
