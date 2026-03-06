# Azure Defender File Scanning

A very simple way to scan files for malware in Azure, using Microsoft Defender for Storage. Works as a synchronous HTTP API that any application can call to get a verdict before trusting a file.

All it does is use an Azure Function to accept a file upload over HTTP, place it into Azure Blob Storage where Microsoft Defender for Storage is enabled, poll the blob metadata until Defender produces a scan verdict, and return the result back to the caller. It uses a User Assigned Managed Identity for all authentication. No keys, no secrets, no nonsense.

# Features

- Synchronous scan verdicts over HTTP - upload a file, get a verdict back
- Two scanning modes: verdict only, or save the file on a safe verdict
- Configurable file extension whitelist via environment variable
- Fully uses Azure Managed Identity - no manual credential management. ever.
- Authenticated callers only - uses Microsoft Entra ID (Azure AD) via App Service Authentication (EasyAuth)
- Only uses the Python standard library, no external libraries
- Automatic cleanup of scanned blobs when not needed
- Automatic cleanup of malicious blobs on unsafe verdicts
- Very easy to audit. Why should you trust me? Trust yourself instead.
- Minimal maintenance overall
- No nonsense. If this has even a hint of nonsense anywhere, it is a bug. File an issue.

# Scanning Modes

- **verdict_only**: Upload a file, get back `{"verdict": "safe"}` or `{"verdict": "unsafe"}`. The blob is always deleted after scanning.
- **save_on_safe**: Upload a file, get back a verdict. If safe, the blob is kept and a `blob_uri` is returned: `{"verdict": "safe", "blob_uri": "https://..."}`. If unsafe, the blob is deleted and only `{"verdict": "unsafe"}` is returned.

# Azure resources shopping list

The list here assumes you will be using dedicated Azure resources for file scanning. Use dedicated resources to uphold a strong security model. Don't cut corners here.

- Azure Storage Account
   - Must have Microsoft Defender for Storage enabled with malware scanning
   - Must have a blob container created for scanning (default name: `av-scanning`)
   - Must be network accessible by the Azure Function
   - Must grant the Azure Function's User Assigned Managed Identity the Azure RBAC role of "Storage Blob Data Contributor"
- Azure Function
   - Must have a User Assigned Managed Identity assigned to it
   - Must have App Service Authentication (EasyAuth) enabled and configured with Microsoft Entra ID
   - Must have the source code from this repo deployed to it
   - Must have outbound network access to the Azure Storage Account
   - Must run on a Flex Consumption App Service Plan, if you enjoy not burning money
- Calling Application (e.g. C# App Service)
   - Must have a Managed Identity (system or user assigned)
   - Must be granted permission to call the Azure Function via Entra ID app role assignment
   - Must acquire a bearer token scoped to the Azure Function's application ID before calling the scan endpoint

# Environment Variables

Sample values are provided below.

- "AV_STORAGE_ACCOUNT_NAME"    = "your-blob-storage-account-name"
- "AV_CONTAINER_NAME"          = "av-scanning"
- "AV_MANAGED_IDENTITY_CLIENT_ID" = "00000000-0000-0000-0000-000000000000"
- "AV_ALLOWED_EXTENSIONS"      = ".pdf,.docx,.xlsx,.pptx,.png,.jpg,.jpeg,.gif,.txt,.csv"
- "AV_SCAN_POLL_INTERVAL"      = "2"
- "AV_SCAN_POLL_TIMEOUT"       = "300"

# Usage

## Request

```
POST /api/scan?filename=report.pdf&mode=verdict_only
Authorization: Bearer <entra-id-token>
Content-Type: application/octet-stream

<raw file bytes>
```

The `filename` query parameter is required. The file extension must be present in the `AV_ALLOWED_EXTENSIONS` whitelist.

The `mode` query parameter is optional and defaults to `verdict_only`. Valid values are `verdict_only` and `save_on_safe`.

## Responses

**Safe file (verdict_only)**
```json
{"verdict": "safe"}
```

**Unsafe file (verdict_only)**
```json
{"verdict": "unsafe"}
```

**Safe file (save_on_safe)**
```json
{"verdict": "safe", "blob_uri": "https://yourstorageaccount.blob.core.windows.net/av-scanning/abc-def/report.pdf"}
```

**Unsafe file (save_on_safe)**
```json
{"verdict": "unsafe"}
```

**Scan timeout (504)**
```json
{"error": "Scan timed out. No verdict was returned by Defender."}
```

# How it works

1. The caller POSTs a file to the Azure Function with a filename and scanning mode
2. The function validates the file extension against the configured whitelist
3. The file is uploaded to Azure Blob Storage under a UUID-prefixed path
4. Microsoft Defender for Storage automatically scans the blob and writes the result to blob metadata (`Malware_Scanning_Result`)
5. The function polls the blob metadata until the scan result appears or a timeout is reached
6. The function returns the verdict to the caller and cleans up the blob as appropriate for the scanning mode

# OpenAPI

An OpenAPI 3.0.3 specification is provided in `openapi.yaml` for integration with API management tooling, client generation, or documentation.

# Disclaimer

This repository is not endorsed by my employer, organisation, clients, anyone, anything or any entity in any way, shape or form. This is released on the internet as a convenience only. No refunds, no "Defender said my file was safe but it ate my production database" support here.
