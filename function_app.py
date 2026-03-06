import json, os, time, logging, uuid
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from datetime import datetime, timedelta, timezone
import azure.functions as func  # type: ignore

app = func.FunctionApp()

STORAGE_ACCOUNT_NAME = os.environ.get("AV_STORAGE_ACCOUNT_NAME")
CONTAINER_NAME = os.environ.get("AV_CONTAINER_NAME", "av-scanning")
MANAGED_IDENTITY_CLIENT_ID = os.environ.get("AV_MANAGED_IDENTITY_CLIENT_ID")
ALLOWED_EXTENSIONS = os.environ.get("AV_ALLOWED_EXTENSIONS", ".pdf,.docx,.xlsx,.pptx,.png,.jpg,.jpeg,.gif,.txt,.csv")
SCAN_POLL_INTERVAL = int(os.environ.get("AV_SCAN_POLL_INTERVAL", "2"))
SCAN_POLL_TIMEOUT = int(os.environ.get("AV_SCAN_POLL_TIMEOUT", "300"))
MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB - Defender for Storage will not scan files larger than this

LOGGER = logging.getLogger(__name__)
LOGGER.addHandler(logging.StreamHandler())
LOGGER.setLevel(logging.INFO)


class BlobStorageAuth:
    def __init__(self):
        self.token = None
        self.token_expires_at = None

    def get_access_token(self):
        if self.token and self.token_expires_at > datetime.now(timezone.utc) + timedelta(minutes=5):
            return self.token
        endpoint = os.getenv("IDENTITY_ENDPOINT")
        identity_header = os.getenv("IDENTITY_HEADER")
        client_id_param = f"&client_id={MANAGED_IDENTITY_CLIENT_ID}" if MANAGED_IDENTITY_CLIENT_ID else ""
        resource_url = f"{endpoint}?resource=https://storage.azure.com/&api-version=2019-08-01{client_id_param}"
        headers = {
            "X-IDENTITY-HEADER": identity_header,
            "Metadata": "true",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        try:
            req = Request(resource_url, headers=headers, method="GET")
            response = urlopen(req, timeout=30)
            if response.status != 200:
                raise Exception(f"Failed to obtain token. Status code: {response.status}")
            response_data = json.loads(response.read())
            self.token = response_data["access_token"]
            self.token_expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
            return self.token
        except URLError as e:
            raise Exception(f"Failed to obtain token: {str(e)}")


class BlobStorageClient:
    def __init__(self, storage_account_name):
        self.storage_account_name = storage_account_name
        self.auth = BlobStorageAuth()
        self.base_url = f"https://{storage_account_name}.blob.core.windows.net"

    def upload_blob(self, container_name, blob_name, content, content_type="application/octet-stream"):
        token = self.auth.get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "x-ms-version": "2021-08-06",
            "x-ms-date": datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "Content-Type": content_type,
            "Content-Length": str(len(content)),
            "x-ms-blob-type": "BlockBlob",
        }
        url = f"{self.base_url}/{container_name}/{blob_name}"
        req = Request(url, headers=headers, method="PUT", data=content)
        urlopen(req)
        return True

    def get_blob_metadata(self, container_name, blob_name):
        token = self.auth.get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "x-ms-version": "2021-08-06",
            "x-ms-date": datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"),
        }
        url = f"{self.base_url}/{container_name}/{blob_name}?comp=metadata"
        req = Request(url, headers=headers, method="GET")
        response = urlopen(req)
        metadata = {}
        for header_name, header_value in response.headers.items():
            if header_name.lower().startswith("x-ms-meta-"):
                key = header_name[len("x-ms-meta-"):]
                metadata[key] = header_value
        return metadata

    def delete_blob(self, container_name, blob_name):
        token = self.auth.get_access_token()
        headers = {
            "Authorization": f"Bearer {token}",
            "x-ms-version": "2021-08-06",
            "x-ms-date": datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT"),
            "x-ms-delete-snapshots": "include",
        }
        url = f"{self.base_url}/{container_name}/{blob_name}"
        req = Request(url, headers=headers, method="DELETE")
        urlopen(req)
        return True

    def get_blob_url(self, container_name, blob_name):
        return f"{self.base_url}/{container_name}/{blob_name}"


def is_extension_allowed(filename):
    allowed = [ext.strip().lower() for ext in ALLOWED_EXTENSIONS.split(",") if ext.strip()]
    _, _, ext = filename.rpartition(".")
    if not ext:
        return False
    return f".{ext.lower()}" in allowed


def poll_scan_result(blob_client, container_name, blob_name):
    t0 = time.time()
    while time.time() - t0 < SCAN_POLL_TIMEOUT:
        try:
            metadata = blob_client.get_blob_metadata(container_name, blob_name)
        except Exception as e:
            LOGGER.warning(f"Error fetching metadata: {e}")
            time.sleep(SCAN_POLL_INTERVAL)
            continue

        scan_result = metadata.get("Malware_Scanning_Result") or metadata.get("malware_scanning_result")
        if scan_result is not None:
            LOGGER.info(f"Scan result for {blob_name}: {scan_result}")
            return scan_result

        LOGGER.info(f"Waiting for scan result on {blob_name}...")
        time.sleep(SCAN_POLL_INTERVAL)

    return None


@app.function_name(name="scan")
@app.route(route="scan", auth_level=func.AuthLevel.ANONYMOUS, methods=["POST"])
def scan_file(req: func.HttpRequest) -> func.HttpResponse:
    mode = req.params.get("mode", "verdict_only")
    if mode not in ("verdict_only", "save_on_safe"):
        return func.HttpResponse(
            json.dumps({"error": "Invalid mode. Use 'verdict_only' or 'save_on_safe'."}),
            status_code=400,
            mimetype="application/json",
        )

    filename = req.params.get("filename")
    if not filename:
        content_disposition = req.headers.get("Content-Disposition", "")
        if "filename=" in content_disposition:
            filename = content_disposition.split("filename=")[-1].strip().strip('"')

    if not filename:
        return func.HttpResponse(
            json.dumps({"error": "A 'filename' query parameter or Content-Disposition header is required."}),
            status_code=400,
            mimetype="application/json",
        )

    if not is_extension_allowed(filename):
        return func.HttpResponse(
            json.dumps({"error": f"File extension not allowed. Allowed: {ALLOWED_EXTENSIONS}"}),
            status_code=400,
            mimetype="application/json",
        )

    file_content = req.get_body()
    if len(file_content) > MAX_FILE_SIZE:
        return func.HttpResponse(
            json.dumps({"error": "File exceeds the maximum allowed size of 2 GB."}),
            status_code=413,
            mimetype="application/json",
        )
    if not file_content:
        return func.HttpResponse(
            json.dumps({"error": "Request body is empty. Provide the file in the request body."}),
            status_code=400,
            mimetype="application/json",
        )

    blob_name = f"{uuid.uuid4()}/{filename}"
    blob_client = BlobStorageClient(STORAGE_ACCOUNT_NAME)

    try:
        content_type = req.headers.get("Content-Type", "application/octet-stream")
        blob_client.upload_blob(CONTAINER_NAME, blob_name, file_content, content_type)
        LOGGER.info(f"Uploaded {blob_name} to {CONTAINER_NAME}")
    except Exception as e:
        LOGGER.error(f"Failed to upload blob: {e}")
        return func.HttpResponse(
            json.dumps({"error": "Failed to upload file for scanning."}),
            status_code=500,
            mimetype="application/json",
        )

    scan_result = poll_scan_result(blob_client, CONTAINER_NAME, blob_name)

    if scan_result is None:
        try:
            blob_client.delete_blob(CONTAINER_NAME, blob_name)
        except Exception:
            pass
        return func.HttpResponse(
            json.dumps({"error": "Scan timed out. No verdict was returned by Defender."}),
            status_code=504,
            mimetype="application/json",
        )

    is_clean = scan_result.lower() in ("no threats found", "no_threats_found")

    if mode == "verdict_only":
        try:
            blob_client.delete_blob(CONTAINER_NAME, blob_name)
        except Exception:
            LOGGER.warning(f"Failed to clean up blob {blob_name}")
        verdict = "safe" if is_clean else "unsafe"
        return func.HttpResponse(
            json.dumps({"verdict": verdict}),
            status_code=200,
            mimetype="application/json",
        )

    if mode == "save_on_safe":
        if is_clean:
            blob_url = blob_client.get_blob_url(CONTAINER_NAME, blob_name)
            return func.HttpResponse(
                json.dumps({"verdict": "safe", "blob_uri": blob_url}),
                status_code=200,
                mimetype="application/json",
            )
        else:
            try:
                blob_client.delete_blob(CONTAINER_NAME, blob_name)
            except Exception:
                LOGGER.warning(f"Failed to clean up malicious blob {blob_name}")
            return func.HttpResponse(
                json.dumps({"verdict": "unsafe"}),
                status_code=200,
                mimetype="application/json",
            )
