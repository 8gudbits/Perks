#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <direct.h>

#define VERSION "1.1"
#define BUFFER_SIZE 8192

typedef enum
{
    ALG_UNKNOWN,
    ALG_MD5,
    ALG_SHA1,
    ALG_SHA256,
    ALG_SHA512
} Algorithm;

FILE *logFile = NULL; // Global log file pointer

void print_banner()
{
    printf("\nPerks %s (x64) : (c) 8gudbits - All rights reserved.\n", VERSION);
    printf("Source - \"https://github.com/8gudbits/8gudbitsKit\"\n\n");
}

void print_help(const char *program_name)
{
    const char *help = 
        "Usage:\n"
        "  %s -[md5|sha1|sha256|sha512] [path] [-f/--file <file.perks>] [-l/--logfile <file.log>]\n"
        "  %s -v/--verify [path] [-f/--file <file.perks>] [-l/--logfile <file.log>]\n"
        "\nOptions:\n"
        "  -h, --help           Show this help message\n"
        "  -n, --nobanner       Suppress the banner display\n"
        "  -f, --file <file>    Specify input/output file (default: <algorithm>.perks)\n"
        "  -v, --verify         Verify files against a previously generated hash file\n"
        "  -l, --logfile <file> Specify log file (default: perks.log)\n"
        "\nExamples:\n"
        "  %s -sha256 C:\\MyFolder\n"
        "  %s -md5 -f hashes.perks -l verification.log\n"
        "  %s -v C:\\MyFolder -f hashes.perks\n"
        "  %s --verify --nobanner -f hashes.perks -l\n";

    printf(help, program_name, program_name, program_name, program_name, program_name, program_name);
    if (logFile) fprintf(logFile, help, program_name, program_name, program_name, program_name, program_name, program_name);
}

const char *algorithm_to_string(Algorithm alg)
{
    switch (alg)
    {
    case ALG_MD5:
        return "md5";
    case ALG_SHA1:
        return "sha1";
    case ALG_SHA256:
        return "sha256";
    case ALG_SHA512:
        return "sha512";
    default:
        return "unknown";
    }
}

Algorithm string_to_algorithm(const char *str)
{
    if (strcmp(str, "md5") == 0)
        return ALG_MD5;
    if (strcmp(str, "sha1") == 0)
        return ALG_SHA1;
    if (strcmp(str, "sha256") == 0)
        return ALG_SHA256;
    if (strcmp(str, "sha512") == 0)
        return ALG_SHA512;
    return ALG_UNKNOWN;
}

bool compute_file_hash(const char *filepath, Algorithm alg, char **hash_str)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BYTE buffer[BUFFER_SIZE];
    DWORD bytesRead;
    BYTE hash[64];
    DWORD hashLen = 0;
    ALG_ID algId;

    switch (alg)
    {
    case ALG_MD5:
        algId = CALG_MD5;
        hashLen = 16;
        break;
    case ALG_SHA1:
        algId = CALG_SHA1;
        hashLen = 20;
        break;
    case ALG_SHA256:
        algId = CALG_SHA_256;
        hashLen = 32;
        break;
    case ALG_SHA512:
        algId = CALG_SHA_512;
        hashLen = 64;
        break;
    default:
        return false;
    }

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        return false;
    }

    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return false;
    }

    hFile = CreateFileA(filepath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    while (ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL) && bytesRead > 0)
    {
        if (!CryptHashData(hHash, buffer, bytesRead, 0))
        {
            CloseHandle(hFile);
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            return false;
        }
    }

    DWORD dummy = hashLen;
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &dummy, 0))
    {
        CloseHandle(hFile);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return false;
    }

    *hash_str = malloc(2 * hashLen + 1);
    for (DWORD i = 0; i < hashLen; i++)
    {
        sprintf(*hash_str + 2 * i, "%02x", hash[i]);
    }
    (*hash_str)[2 * hashLen] = '\0';

    CloseHandle(hFile);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return true;
}

void process_directory(const char *basePath, const char *relativePath, Algorithm alg, FILE *outFile)
{
    char path[MAX_PATH];
    if (strlen(relativePath) == 0)
    {
        snprintf(path, MAX_PATH, "%s\\*", basePath);
    }
    else
    {
        snprintf(path, MAX_PATH, "%s\\%s\\*", basePath, relativePath);
    }

    WIN32_FIND_DATAA findFileData;
    HANDLE hFind = FindFirstFileA(path, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE)
        return;

    do
    {
        if (strcmp(findFileData.cFileName, ".") == 0 || strcmp(findFileData.cFileName, "..") == 0)
        {
            continue;
        }

        char newRelativePath[MAX_PATH];
        if (relativePath[0] == '\0')
        {
            snprintf(newRelativePath, MAX_PATH, "%s", findFileData.cFileName);
        }
        else
        {
            snprintf(newRelativePath, MAX_PATH, "%s\\%s", relativePath, findFileData.cFileName);
        }

        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s\\%s", basePath, newRelativePath);

        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            process_directory(basePath, newRelativePath, alg, outFile);
        }
        else
        {
            // Show progress: <algorithm>: <filepath>
            const char *progress = "%s: %s\n";
            printf(progress, algorithm_to_string(alg), newRelativePath);
            if (logFile) fprintf(logFile, progress, algorithm_to_string(alg), newRelativePath);

            char *hash = NULL;
            if (compute_file_hash(fullPath, alg, &hash))
            {
                // Format: <hash> <filename>
                fprintf(outFile, "%s %s\n", hash, newRelativePath);
                free(hash);
            }
        }
    } while (FindNextFileA(hFind, &findFileData) != 0);

    FindClose(hFind);
}

bool generate_hashes(const char *path, Algorithm alg, const char *outFile)
{
    FILE *file = fopen(outFile, "w");
    if (!file)
    {
        const char *error = "Failed to open output file: %s\n";
        printf(error, outFile);
        if (logFile) fprintf(logFile, error, outFile);
        return false;
    }

    // Write header with algorithm information
    fprintf(file, "#PERKSv1.0 %s\n", algorithm_to_string(alg));
    process_directory(path, "", alg, file);
    fclose(file);

    // Show where the file was saved
    char absolutePath[MAX_PATH];
    const char *saved = "\nHash file saved to: %s\n";
    if (_fullpath(absolutePath, outFile, MAX_PATH) != NULL)
    {
        printf(saved, absolutePath);
        if (logFile) fprintf(logFile, saved, absolutePath);
    }
    else
    {
        printf(saved, outFile);
        if (logFile) fprintf(logFile, saved, outFile);
    }

    return true;
}

bool verify_hashes(const char *path, const char *inFile)
{
    FILE *file = fopen(inFile, "r");
    if (!file)
    {
        const char *error = "Failed to open input file: %s\n";
        printf(error, inFile);
        if (logFile) fprintf(logFile, error, inFile);
        return false;
    }

    char header[256];
    if (!fgets(header, sizeof(header), file))
    {
        fclose(file);
        const char *error = "Failed to read header from input file\n";
        printf(error);
        if (logFile) fprintf(logFile, error);
        return false;
    }

    char algoStr[64];
    if (sscanf(header, "#PERKSv1.0 %63s", algoStr) != 1)
    {
        fclose(file);
        const char *error = "Invalid header format in input file\n";
        printf(error);
        if (logFile) fprintf(logFile, error);
        return false;
    }

    Algorithm alg = string_to_algorithm(algoStr);
    if (alg == ALG_UNKNOWN)
    {
        fclose(file);
        const char *error = "Unknown algorithm in input file: %s\n";
        printf(error, algoStr);
        if (logFile) fprintf(logFile, error, algoStr);
        return false;
    }

    char line[1024];
    bool success = true;
    int totalFiles = 0;
    int passedFiles = 0;
    int failedFiles = 0;
    int missingFiles = 0;

    while (fgets(line, sizeof(line), file))
    {
        // Skip empty lines and comments
        if (line[0] == '\n' || line[0] == '#')
            continue;

        // Parse format: <hash> <filename>
        char expectedHash[256];
        char filePath[MAX_PATH];

        if (sscanf(line, "%255s %[^\n]", expectedHash, filePath) != 2)
        {
            continue;
        }

        totalFiles++;
        char fullPath[MAX_PATH];
        snprintf(fullPath, MAX_PATH, "%s\\%s", path, filePath);

        // Check if file exists first
        DWORD fileAttributes = GetFileAttributesA(fullPath);
        if (fileAttributes == INVALID_FILE_ATTRIBUTES || (fileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            const char *missing = "[MISSING] %s\n";
            printf(missing, filePath);
            if (logFile) fprintf(logFile, missing, filePath);
            success = false;
            missingFiles++;
            continue;
        }

        char *actualHash = NULL;
        if (!compute_file_hash(fullPath, alg, &actualHash))
        {
            const char *failed = "[FAILED] %s (Unable to compute hash)\n";
            printf(failed, filePath);
            if (logFile) fprintf(logFile, failed, filePath);
            success = false;
            failedFiles++;
            continue;
        }

        if (strcmp(actualHash, expectedHash) == 0)
        {
            const char *pass = "[PASS] %s\n";
            printf(pass, filePath);
            if (logFile) fprintf(logFile, pass, filePath);
            passedFiles++;
        }
        else
        {
            const char *fail = "[FAIL] %s\n";
            printf(fail, filePath);
            if (logFile) fprintf(logFile, fail, filePath);
            success = false;
            failedFiles++;
        }
        free(actualHash);
    }

    fclose(file);

    // Print summary
    const char *summary = 
        "\nVerification complete:\n"
        "  Total files: %d\n"
        "  Passed: %d\n"
        "  Failed: %d\n"
        "  Missing: %d\n";
    
    printf(summary, totalFiles, passedFiles, failedFiles, missingFiles);
    if (logFile) fprintf(logFile, summary, totalFiles, passedFiles, failedFiles, missingFiles);

    return success;
}

void cleanup_logfile()
{
    if (logFile)
    {
        fclose(logFile);
        logFile = NULL;
    }
}

int main(int argc, char *argv[])
{
    bool showBanner = true;
    bool showHelp = false;
    Algorithm alg = ALG_UNKNOWN;
    const char *path = ".";
    const char *file = NULL;
    const char *logFileName = NULL;
    bool verifyMode = false;
    bool fileSpecified = false;
    bool logFileSpecified = false;

    // Parse command line arguments
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
        {
            showHelp = true;
        }
        else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--nobanner") == 0)
        {
            showBanner = false;
        }
        else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verify") == 0)
        {
            verifyMode = true;
        }
        else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0)
        {
            if (i + 1 < argc)
            {
                file = argv[++i];
                fileSpecified = true;
            }
        }
        else if (strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "--logfile") == 0)
        {
            logFileSpecified = true;
            if (i + 1 < argc && argv[i + 1][0] != '-')
            {
                logFileName = argv[++i];
            }
            else
            {
                logFileName = "perks.log";
            }
        }
        else if (strncmp(argv[i], "-", 1) == 0)
        {
            if (strcmp(argv[i], "-md5") == 0)
                alg = ALG_MD5;
            else if (strcmp(argv[i], "-sha1") == 0)
                alg = ALG_SHA1;
            else if (strcmp(argv[i], "-sha256") == 0)
                alg = ALG_SHA256;
            else if (strcmp(argv[i], "-sha512") == 0)
                alg = ALG_SHA512;
        }
        else
        {
            // This should be the path argument
            path = argv[i];
        }
    }

    // Set up log file if specified
    if (logFileSpecified)
    {
        logFile = fopen(logFileName, "w");
        if (!logFile)
        {
            printf("Warning: Could not open log file %s for writing\n", logFileName);
        }
    }

    // Register cleanup function
    atexit(cleanup_logfile);

    if (showBanner)
    {
        print_banner();
    }

    if (showHelp)
    {
        print_help(argv[0]);
        return 0;
    }

    // Handle default file naming
    if (!fileSpecified)
    {
        if (verifyMode)
        {
            const char *error = "Error: Input file must be specified in verify mode.\n";
            printf(error);
            if (logFile) fprintf(logFile, error);
            print_help(argv[0]);
            return 1;
        }
        else if (alg != ALG_UNKNOWN)
        {
            char defaultFile[MAX_PATH];
            sprintf(defaultFile, "%s.perks", algorithm_to_string(alg));
            file = _strdup(defaultFile);
        }
    }

    if (verifyMode)
    {
        if (!file)
        {
            const char *error = "Error: Input file must be specified in verify mode.\n";
            printf(error);
            if (logFile) fprintf(logFile, error);
            print_help(argv[0]);
            return 1;
        }
        return verify_hashes(path, file) ? 0 : 1;
    }
    else
    {
        if (alg == ALG_UNKNOWN)
        {
            const char *error = "Error: No algorithm specified.\n";
            printf(error);
            if (logFile) fprintf(logFile, error);
            print_help(argv[0]);
            return 1;
        }
        if (!file)
        {
            const char *error = "Error: Output file must be specified.\n";
            printf(error);
            if (logFile) fprintf(logFile, error);
            print_help(argv[0]);
            return 1;
        }
        return generate_hashes(path, alg, file) ? 0 : 1;
    }
}

