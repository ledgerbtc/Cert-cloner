#pragma once
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <mscat.h>
#include <imagehlp.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <memory>
#include <fstream>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "imagehlp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

class CertificateCloneTool {
public:
    struct CertificateInfo {
        std::wstring subjectName;
        std::wstring issuerName;
        std::wstring serialNumber;
        std::wstring thumbprint;
        std::vector<BYTE> certificateData;
        std::vector<BYTE> signatureData;
        DWORD signatureSize;
        DWORD checksum;
        bool isValid;
    };

    CertificateCloneTool();
    ~CertificateCloneTool();

    bool ExtractCertificate(const std::wstring& sourceFile, CertificateInfo& certInfo);

    bool ApplyCertificate(const std::wstring& targetFile, const CertificateInfo& certInfo);

    bool VerifyCertificate(const std::wstring& filePath, std::wstring& statusMessage);

    std::wstring GetFileHash(const std::wstring& filePath);

    bool SaveCertificateToFile(const CertificateInfo& certInfo, const std::wstring& outputFile);

    bool LoadCertificateFromFile(const std::wstring& inputFile, CertificateInfo& certInfo);

private:
    bool ExtractCertificateData(PCCERT_CONTEXT certContext, std::vector<BYTE>& certData);
    bool GetSignatureFromFile(const std::wstring& filePath, std::vector<BYTE>& signatureData, DWORD& signatureSize);
    bool ApplySignatureToFile(const std::wstring& filePath, const std::vector<BYTE>& signatureData, DWORD signatureSize);
    bool RecalculatePEChecksum(const std::wstring& filePath);
    std::wstring GetCertificateName(PCCERT_CONTEXT certContext, DWORD type);
    std::wstring GetSerialNumberString(PCCERT_CONTEXT certContext);
    std::wstring GetThumbprint(PCCERT_CONTEXT certContext);
};