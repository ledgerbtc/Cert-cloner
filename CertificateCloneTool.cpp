#include "CertificateCloneTool.h"
#include <iostream>
#include <iomanip>
#include <sstream>

CertificateCloneTool::CertificateCloneTool() {}

CertificateCloneTool::~CertificateCloneTool() {}

bool CertificateCloneTool::ExtractCertificate(const std::wstring& sourceFile, CertificateInfo& certInfo) {
    HANDLE hFile = CreateFileW(
        sourceFile.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open file. Error: " << GetLastError() << std::endl;
        return false;
    }

    DWORD bytesRead = 0;

    IMAGE_DOS_HEADER dosHeader;
    if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Not a valid PE file" << std::endl;
        CloseHandle(hFile);
        return false;
    }

    SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN);
    DWORD peSig;
    if (!ReadFile(hFile, &peSig, sizeof(peSig), &bytesRead, nullptr) || peSig != IMAGE_NT_SIGNATURE) {
        std::cerr << "Not a valid PE file" << std::endl;
        CloseHandle(hFile);
        return false;
    }

    IMAGE_FILE_HEADER fileHeader;
    ReadFile(hFile, &fileHeader, sizeof(fileHeader), &bytesRead, nullptr);

    WORD magic;
    ReadFile(hFile, &magic, sizeof(magic), &bytesRead, nullptr);

    DWORD securityDirRva = 0;
    DWORD securityDirSize = 0;
    std::vector<BYTE> optBuffer(fileHeader.SizeOfOptionalHeader);
    SetFilePointer(hFile, -2, nullptr, FILE_CURRENT);
    ReadFile(hFile, optBuffer.data(), (DWORD)optBuffer.size(), &bytesRead, nullptr);

    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        auto opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(optBuffer.data());
        securityDirRva = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        securityDirSize = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        certInfo.checksum = opt->CheckSum;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optBuffer.data());
        securityDirRva = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
        securityDirSize = opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
        certInfo.checksum = opt->CheckSum;
    }

    if (securityDirRva == 0 || securityDirSize == 0) {
        std::cerr << "No Authenticode signature found (RVA=" << securityDirRva << ", Size=" << securityDirSize << ")" << std::endl;
        CloseHandle(hFile);
        return false;
    }

    std::vector<BYTE> secBlob(securityDirSize);
    SetFilePointer(hFile, securityDirRva, nullptr, FILE_BEGIN);
    if (!ReadFile(hFile, secBlob.data(), securityDirSize, &bytesRead, nullptr) || bytesRead != securityDirSize) {
        std::cerr << "Failed to read security directory" << std::endl;
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    certInfo.signatureData = secBlob;
    WIN_CERTIFICATE* certHeader = reinterpret_cast<WIN_CERTIFICATE*>(secBlob.data());
    certInfo.signatureSize = certHeader->dwLength;

    DWORD headerSize = sizeof(WIN_CERTIFICATE) - sizeof(BYTE);
    DWORD pkcs7Size = certHeader->dwLength - headerSize;

    CRYPT_DATA_BLOB pkcs7Blob;
    pkcs7Blob.cbData = pkcs7Size;
    pkcs7Blob.pbData = certHeader->bCertificate;

    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;
    PCCERT_CONTEXT pCertContext = nullptr;
    DWORD dwEncoding, dwContentType, dwFormatType;

    if (!CryptQueryObject(
        CERT_QUERY_OBJECT_BLOB,
        &pkcs7Blob,
        CERT_QUERY_CONTENT_FLAG_ALL,
        CERT_QUERY_FORMAT_FLAG_BINARY,
        0,
        &dwEncoding,
        &dwContentType,
        &dwFormatType,
        &hStore,
        &hMsg,
        (const void**)&pCertContext)) {

        std::cerr << "CryptQueryObject on PKCS#7 blob failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (!pCertContext && hStore) {
        pCertContext = CertEnumCertificatesInStore(hStore, nullptr);
    }

    if (!pCertContext) {
        std::cerr << "No certificate context found in PKCS#7 blob. Error: " << GetLastError() << std::endl;
        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);
        return false;
    }

    certInfo.isValid = true;
    certInfo.subjectName = GetCertificateName(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE);
    certInfo.issuerName = GetCertificateName(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE);

    if (pCertContext->pCertInfo) {
        DWORD issuerSize = CertGetNameStringW(
            pCertContext,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            CERT_NAME_ISSUER_FLAG,
            nullptr,
            nullptr,
            0
        );
        if (issuerSize > 1) {
            std::vector<wchar_t> issuerBuf(issuerSize);
            CertGetNameStringW(
                pCertContext,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                CERT_NAME_ISSUER_FLAG,
                nullptr,
                issuerBuf.data(),
                issuerSize
            );
            certInfo.issuerName = std::wstring(issuerBuf.data());
        }
    }
    certInfo.serialNumber = GetSerialNumberString(pCertContext);
    certInfo.thumbprint = GetThumbprint(pCertContext);
    ExtractCertificateData(pCertContext, certInfo.certificateData);

    if (pCertContext) CertFreeCertificateContext(pCertContext);
    if (hStore) CertCloseStore(hStore, 0);
    if (hMsg) CryptMsgClose(hMsg);

    return certInfo.isValid;
}

bool CertificateCloneTool::ApplyCertificate(const std::wstring& targetFile, const CertificateInfo& certInfo) {
    if (!certInfo.isValid || certInfo.certificateData.empty()) {
        std::cerr << "Invalid certificate information" << std::endl;
        return false;
    }

    if (!ApplySignatureToFile(targetFile, certInfo.signatureData, certInfo.signatureSize)) {
        std::cerr << "Failed to apply signature to file" << std::endl;
        return false;
    }

    if (!RecalculatePEChecksum(targetFile)) {
        std::cerr << "Failed to recalculate PE checksum" << std::endl;
        return false;
    }

    return true;
}

bool CertificateCloneTool::VerifyCertificate(const std::wstring& filePath, std::wstring& statusMessage) {
    WINTRUST_FILE_INFO fileInfo = { 0 };
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = filePath.c_str();
    fileInfo.hFile = nullptr;
    fileInfo.pgKnownSubject = nullptr;

    WINTRUST_DATA wintrustData = { 0 };
    wintrustData.cbStruct = sizeof(WINTRUST_DATA);
    wintrustData.pPolicyCallbackData = nullptr;
    wintrustData.pSIPClientData = nullptr;
    wintrustData.dwUIChoice = WTD_UI_NONE;
    wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
    wintrustData.pFile = &fileInfo;
    wintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
    wintrustData.hWVTStateData = nullptr;
    wintrustData.pwszURLReference = nullptr;
    wintrustData.dwProvFlags = 0;
    wintrustData.dwUIContext = WTD_UI_NONE;

    LONG lStatus = WinVerifyTrust(
        nullptr,
        &policyGUID,
        &wintrustData
    );

    switch (lStatus) {
    case ERROR_SUCCESS:
        statusMessage = L"Certificate verified successfully";
        return true;
    case TRUST_E_NOSIGNATURE:
        statusMessage = L"No signature found";
        return false;
    case TRUST_E_EXPLICIT_DISTRUST:
        statusMessage = L"Certificate explicitly distrusted";
        return false;
    case TRUST_E_SUBJECT_NOT_TRUSTED:
        statusMessage = L"Certificate subject not trusted";
        return false;
    case CERT_E_UNTRUSTEDROOT:
        statusMessage = L"Untrusted root certificate";
        return false;
    case TRUST_E_BAD_DIGEST:
        statusMessage = L"Bad digest";
        return false;
    default:
        statusMessage = L"Certificate verification failed with status: " + std::to_wstring(lStatus);
        return false;
    }
}

bool CertificateCloneTool::SaveCertificateToFile(const CertificateInfo& certInfo, const std::wstring& outputFile) {
    std::ofstream outFile(outputFile, std::ios::binary);
    if (!outFile) {
        std::cerr << "Failed to open output file for writing" << std::endl;
        return false;
    }

    DWORD magic = 0x43455254; 
    DWORD version = 2;
    DWORD certSize = (DWORD)certInfo.certificateData.size();
    DWORD sigSize = certInfo.signatureSize;

    outFile.write(reinterpret_cast<char*>(&magic), sizeof(magic));
    outFile.write(reinterpret_cast<char*>(&version), sizeof(version));
    outFile.write(reinterpret_cast<char*>(&certSize), sizeof(certSize));
    outFile.write(reinterpret_cast<char*>(&sigSize), sizeof(sigSize));
    outFile.write(reinterpret_cast<const char*>(&certInfo.checksum), sizeof(certInfo.checksum));

    if (!certInfo.certificateData.empty()) {
        outFile.write(reinterpret_cast<const char*>(certInfo.certificateData.data()), certInfo.certificateData.size());
    }

    if (!certInfo.signatureData.empty()) {
        outFile.write(reinterpret_cast<const char*>(certInfo.signatureData.data()), certInfo.signatureData.size());
    }

    outFile.close();
    return true;
}

bool CertificateCloneTool::LoadCertificateFromFile(const std::wstring& inputFile, CertificateInfo& certInfo) {
    std::ifstream inFile(inputFile, std::ios::binary);
    if (!inFile) {
        std::cerr << "Failed to open input file for reading" << std::endl;
        return false;
    }

    DWORD magic, version, certSize, sigSize;
    inFile.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    inFile.read(reinterpret_cast<char*>(&version), sizeof(version));
    inFile.read(reinterpret_cast<char*>(&certSize), sizeof(certSize));
    inFile.read(reinterpret_cast<char*>(&sigSize), sizeof(sigSize));

    if (magic != 0x43455254 || (version != 1 && version != 2)) {
        std::cerr << "Invalid certificate file format" << std::endl;
        return false;
    }

    if (version >= 2) {
        inFile.read(reinterpret_cast<char*>(&certInfo.checksum), sizeof(certInfo.checksum));
    } else {
        certInfo.checksum = 0;
    }

    certInfo.certificateData.resize(certSize);
    if (certSize > 0) {
        inFile.read(reinterpret_cast<char*>(certInfo.certificateData.data()), certSize);
    }

    certInfo.signatureData.resize(sigSize);
    certInfo.signatureSize = sigSize;
    if (sigSize > 0) {
        inFile.read(reinterpret_cast<char*>(certInfo.signatureData.data()), sigSize);
    }

    certInfo.isValid = true;
    inFile.close();
    return true;
}

bool CertificateCloneTool::ExtractCertificateData(PCCERT_CONTEXT certContext, std::vector<BYTE>& certData) {
    if (!certContext) return false;

    certData.resize(certContext->cbCertEncoded);
    memcpy(certData.data(), certContext->pbCertEncoded, certContext->cbCertEncoded);
    return true;
}

bool CertificateCloneTool::GetSignatureFromFile(const std::wstring& filePath, std::vector<BYTE>& signatureData, DWORD& signatureSize) {
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open file. Error: " << GetLastError() << std::endl;
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);

    DWORD certCount = 0;
    BOOL result = ImageEnumerateCertificates(
        hFile,
        CERT_SECTION_TYPE_ANY,
        &certCount,
        nullptr,
        0
    );

    if (!result || certCount == 0) {
        std::cerr << "No certificates found in file" << std::endl;
        CloseHandle(hFile);
        return false;
    }

    DWORD certSize = 0;
    ImageGetCertificateData(hFile, 0, nullptr, &certSize);

    if (certSize == 0) {
        std::cerr << "Failed to get certificate size" << std::endl;
        CloseHandle(hFile);
        return false;
    }

    std::vector<BYTE> certBuffer(certSize);
    WIN_CERTIFICATE* certHeader = reinterpret_cast<WIN_CERTIFICATE*>(certBuffer.data());

    if (!ImageGetCertificateData(hFile, 0, certHeader, &certSize)) {
        std::cerr << "Failed to get certificate data. Error: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return false;
    }

    DWORD headerSize = sizeof(WIN_CERTIFICATE) - sizeof(BYTE);
    signatureSize = certHeader->dwLength - headerSize;
    signatureData.resize(signatureSize);
    memcpy(signatureData.data(), certHeader->bCertificate, signatureSize);

    CloseHandle(hFile);
    return true;
}

bool CertificateCloneTool::ApplySignatureToFile(const std::wstring& filePath, const std::vector<BYTE>& signatureData, DWORD signatureSize) {
    if (signatureSize < sizeof(WIN_CERTIFICATE) || signatureData.size() < signatureSize) {
        std::cerr << "Invalid signature data" << std::endl;
        return false;
    }

    WIN_CERTIFICATE* certHeader = reinterpret_cast<WIN_CERTIFICATE*>(const_cast<BYTE*>(signatureData.data()));
    std::wcout << L"WIN_CERTIFICATE: dwLength=" << certHeader->dwLength
        << L" wRevision=0x" << std::hex << certHeader->wRevision
        << L" wCertificateType=0x" << certHeader->wCertificateType
        << std::dec << L"\n";

    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open target file. Error: " << GetLastError() << std::endl;
        return false;
    }

    DWORD bytesRead = 0;

    IMAGE_DOS_HEADER dosHeader;
    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    if (!ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, nullptr) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cerr << "Invalid DOS header" << std::endl;
        CloseHandle(hFile);
        return false;
    }

    SetFilePointer(hFile, dosHeader.e_lfanew, nullptr, FILE_BEGIN);
    DWORD peSig;
    if (!ReadFile(hFile, &peSig, sizeof(peSig), &bytesRead, nullptr) || peSig != IMAGE_NT_SIGNATURE) {
        std::cerr << "Invalid PE signature" << std::endl;
        CloseHandle(hFile);
        return false;
    }

    IMAGE_FILE_HEADER fileHeader;
    if (!ReadFile(hFile, &fileHeader, sizeof(fileHeader), &bytesRead, nullptr)) {
        CloseHandle(hFile);
        return false;
    }

    WORD magic;
    if (!ReadFile(hFile, &magic, sizeof(magic), &bytesRead, nullptr)) {
        CloseHandle(hFile);
        return false;
    }

    std::vector<BYTE> optBuffer(fileHeader.SizeOfOptionalHeader);
    SetFilePointer(hFile, -2, nullptr, FILE_CURRENT);
    if (!ReadFile(hFile, optBuffer.data(), (DWORD)optBuffer.size(), &bytesRead, nullptr)) {
        CloseHandle(hFile);
        return false;
    }

    DWORD secDirOffset = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        auto opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(optBuffer.data());
        secDirOffset = (DWORD)(reinterpret_cast<BYTE*>(&opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]) - optBuffer.data());
        std::wcout << L"PE32 - Existing security dir: VA=0x" << std::hex
            << opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
            << L" Size=0x" << opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size
            << std::dec << L"\n";
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        auto opt = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(optBuffer.data());
        secDirOffset = (DWORD)(reinterpret_cast<BYTE*>(&opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]) - optBuffer.data());
        std::wcout << L"PE64 - Existing security dir: VA=0x" << std::hex
            << opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress
            << L" Size=0x" << opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size
            << std::dec << L"\n";
    } else {
        std::cerr << "Unknown optional header magic: " << magic << std::endl;
        CloseHandle(hFile);
        return false;
    }

    DWORD entryFileOffset = dosHeader.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + secDirOffset;

    DWORD fileSize = SetFilePointer(hFile, 0, nullptr, FILE_END);
    if (fileSize == INVALID_SET_FILE_POINTER) {
        std::cerr << "Failed to get file size. Error: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return false;
    }

    DWORD certOffset = (fileSize + 7) & ~7u;
    DWORD padBytes = certOffset - fileSize;

    if (padBytes > 0) {
        std::vector<BYTE> padding(padBytes, 0);
        SetFilePointer(hFile, fileSize, nullptr, FILE_BEGIN);
        DWORD bytesWritten = 0;
        if (!WriteFile(hFile, padding.data(), padBytes, &bytesWritten, nullptr) || bytesWritten != padBytes) {
            std::cerr << "Failed to write padding. Error: " << GetLastError() << std::endl;
            CloseHandle(hFile);
            return false;
        }
    }

    SetFilePointer(hFile, certOffset, nullptr, FILE_BEGIN);
    DWORD bytesWritten = 0;
    if (!WriteFile(hFile, signatureData.data(), signatureSize, &bytesWritten, nullptr) || bytesWritten != signatureSize) {
        std::cerr << "Failed to write certificate. Error: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return false;
    }
    std::wcout << L"Wrote " << bytesWritten << L" bytes at offset 0x" << std::hex << certOffset << std::dec << L"\n";

    IMAGE_DATA_DIRECTORY newSecDir;
    newSecDir.VirtualAddress = certOffset;
    newSecDir.Size = signatureSize;

    SetFilePointer(hFile, entryFileOffset, nullptr, FILE_BEGIN);
    if (!WriteFile(hFile, &newSecDir, sizeof(newSecDir), &bytesWritten, nullptr) || bytesWritten != sizeof(newSecDir)) {
        std::cerr << "Failed to update security directory. Error: " << GetLastError() << std::endl;
        CloseHandle(hFile);
        return false;
    }

    std::wcout << L"Security dir updated at file offset 0x" << std::hex << entryFileOffset
        << L" -> VA=0x" << newSecDir.VirtualAddress << L" Size=0x" << newSecDir.Size
        << std::dec << L"\n";

    FlushFileBuffers(hFile);
    CloseHandle(hFile);

    hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE) {
        SetFilePointer(hFile, entryFileOffset, nullptr, FILE_BEGIN);
        IMAGE_DATA_DIRECTORY verifyDir = {};
        ReadFile(hFile, &verifyDir, sizeof(verifyDir), &bytesRead, nullptr);
        std::wcout << L"Verify readback - Security Dir: VA=0x" << std::hex << verifyDir.VirtualAddress
            << L" Size=0x" << verifyDir.Size << std::dec << L"\n";

        SetFilePointer(hFile, verifyDir.VirtualAddress, nullptr, FILE_BEGIN);
        WIN_CERTIFICATE verifyCert = {};
        ReadFile(hFile, &verifyCert, sizeof(verifyCert), &bytesRead, nullptr);
        std::wcout << L"Verify certificate - dwLength=" << verifyCert.dwLength
            << L" wRevision=0x" << std::hex << verifyCert.wRevision
            << L" wCertificateType=0x" << verifyCert.wCertificateType
            << std::dec << L"\n";

        DWORD certCount = 0;
        ImageEnumerateCertificates(hFile, CERT_SECTION_TYPE_ANY, &certCount, nullptr, 0);
        std::wcout << L"ImageEnumerateCertificates count: " << certCount << L"\n";

        CloseHandle(hFile);
    }

    return true;
}

bool CertificateCloneTool::RecalculatePEChecksum(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open file for checksum recalculation. Error: " << GetLastError() << std::endl;
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, nullptr);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    std::vector<BYTE> fileData(fileSize);
    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, fileData.data(), fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
        CloseHandle(hFile);
        return false;
    }

    IMAGE_DOS_HEADER* dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(fileData.data());
    if (dosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
        CloseHandle(hFile);
        return false;
    }

    DWORD* peSig = reinterpret_cast<DWORD*>(fileData.data() + dosHdr->e_lfanew);
    if (*peSig != IMAGE_NT_SIGNATURE) {
        CloseHandle(hFile);
        return false;
    }

    DWORD checksumOffset = dosHdr->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + 64;
    if (checksumOffset + 4 > fileSize) {
        CloseHandle(hFile);
        return false;
    }

    DWORD* checksumField = reinterpret_cast<DWORD*>(fileData.data() + checksumOffset);
    *checksumField = 0;

    DWORD checksum = 0;
    for (DWORD i = 0; i + 1 < fileSize; i += 2) {
        if (i == checksumOffset || i == checksumOffset + 2) continue;
        WORD word = *reinterpret_cast<WORD*>(fileData.data() + i);
        checksum += word;
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }
    if (fileSize & 1) {
        checksum += fileData[fileSize - 1];
        checksum = (checksum & 0xFFFF) + (checksum >> 16);
    }

    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum += fileSize;

    SetFilePointer(hFile, checksumOffset, nullptr, FILE_BEGIN);
    DWORD bytesWritten = 0;
    WriteFile(hFile, &checksum, sizeof(checksum), &bytesWritten, nullptr);

    CloseHandle(hFile);
    return true;
}

std::wstring CertificateCloneTool::GetFileHash(const std::wstring& filePath) {
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        return L"Failed to open file";
    }

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::wstring result = L"Hash calculation failed";

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0) {
        if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) >= 0) {
            BYTE buffer[8192];
            DWORD bytesRead = 0;
            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > 0) {
                BCryptHashData(hHash, buffer, bytesRead, 0);
            }

            BYTE hash[32];
            if (BCryptFinishHash(hHash, hash, sizeof(hash), 0) >= 0) {
                std::wstringstream ss;
                ss << std::hex << std::setfill(L'0');
                for (DWORD i = 0; i < sizeof(hash); i++) {
                    ss << std::setw(2) << static_cast<int>(hash[i]);
                }
                result = ss.str();
            }
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    CloseHandle(hFile);
    return result;
}

std::wstring CertificateCloneTool::GetCertificateName(PCCERT_CONTEXT certContext, DWORD type) {
    if (!certContext) return L"Unknown";

    DWORD nameSize = CertGetNameStringW(
        certContext,
        type,
        0,
        nullptr,
        nullptr,
        0
    );

    if (nameSize <= 1) return L"Unknown";

    std::vector<wchar_t> nameBuffer(nameSize);
    CertGetNameStringW(
        certContext,
        type,
        0,
        nullptr,
        nameBuffer.data(),
        nameSize
    );

    return std::wstring(nameBuffer.data());
}

std::wstring CertificateCloneTool::GetSerialNumberString(PCCERT_CONTEXT certContext) {
    if (!certContext || !certContext->pCertInfo) return L"Unknown";

    CRYPT_INTEGER_BLOB* serialNumber = &certContext->pCertInfo->SerialNumber;

    std::wstringstream ss;
    ss << L"0x";
    for (DWORD i = 0; i < serialNumber->cbData; i++) {
        ss << std::hex << std::setw(2) << std::setfill(L'0')
            << static_cast<int>(serialNumber->pbData[i]);
    }

    return ss.str();
}

std::wstring CertificateCloneTool::GetThumbprint(PCCERT_CONTEXT certContext) {
    if (!certContext) return L"Unknown";

    BYTE hash[20]; 
    DWORD hashSize = sizeof(hash);

    if (!CertGetCertificateContextProperty(
        certContext,
        CERT_HASH_PROP_ID,
        hash,
        &hashSize
    )) {
        return L"Unknown";
    }

    std::wstringstream ss;
    for (DWORD i = 0; i < hashSize; i++) {
        ss << std::hex << std::setw(2) << std::setfill(L'0')
            << static_cast<int>(hash[i]);
        if (i < hashSize - 1) ss << L" ";
    }

    return ss.str();
}