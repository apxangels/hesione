import yaml
from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    Depends,
    Path,
    Security,
    Response,
)
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.security.utils import get_authorization_scheme_param
import httpx
from typing import Dict, Optional
from starlette.routing import Match
import base64
import app.routines as routines
from urllib.parse import urlencode, parse_qs

import logging

logger = logging.getLogger("main")
logger.setLevel(logging.INFO)
logger.disabled = False

handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)

if not logger.hasHandlers():  # защищаем от дублирующих выводов
    logger.addHandler(handler)


# gathering config values
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

receiver_map = {r["name"]: r for r in config["receivers"]}
security = HTTPBasic()

app = FastAPI()


async def optional_credentials(
    request: Request,
) -> Optional[HTTPBasicCredentials]:
    auth = request.headers.get("Authorization")
    scheme, _ = get_authorization_scheme_param(auth)
    if not auth or scheme.lower() != "basic":
        return None
    return await security(request)


## Service endpoint for grabing proxy status
@app.get("/health")
async def health_check():
    result = []
    for receiver in receiver_map.values():
        entry = {
            "name": receiver["name"],
            "prom_url": receiver["prom"],
            "label_name": receiver["label_name"],
            "label_value": receiver["label"],
            "auth": "yes" if "auth" in receiver else "no",
            "prom_auth": "yes" if "prom_auth" in receiver else "no",
        }
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                urls = [
                    f'{receiver["prom"]}/-/health',
                    f'{receiver["prom"]}/-/healthy',
                    f'{receiver["prom"]}/-/ready',
                ]
                prom_auth = routines.get_prom_auth(receiver, None)

                # There are many health endpoints in prom applications, so we need to check them 1by1
                for url in urls:
                    resp = await client.get(url, auth=prom_auth)
                    logger.info(f"Trying {url}")
                    if resp.status_code == 200:
                        entry["status"] = "up"
                        logger.info(f"{url} is up!")
                        break
                    else:
                        entry["status"] = f"bad ({resp.status_code})"
                        logger.warning(
                            f"{url} is not up, code {resp.status_code}"
                        )
                else:
                    entry["status"] = "down (all checks failed)"
        except httpx.RequestError as e:
            entry["status"] = f"down ({str(e)})"
        except Exception as e:
            entry["status"] = f"down (unexpected error: {str(e)})"

        result.append(entry)

    return JSONResponse(content={"receivers": result})


"""
There are two types of requests from clients to proms
The 1st type is 
Request: GET vmauth:8427/api/v1/status/buildinfo or prometheus:9090/api/v1/query. 
They are shouldnt be changed

The 2nd type is 
Request: POST vmauth:8427/api/v1/query_range b'end=1753795200&query=%7Bjob%3D%22elastic_exp2%22%7D&start=1753791600&step=15' {'user-agent': 'Grafana/11.3.2', 'content-length': '76', 'content-type': 'application/x-www-form-urlencoded', 'x-datasource-uid': 'cetdl7r70z4zke', 'x-grafana-id': 'eyJhbGciOiJFUzI1NiIsImtpZCI6ImlkLTIwMjUtMDctZXMyNTYiLCJ0eXAiOiJqd3QifQ.eyJhdWQiOiJvcmc6MSIsImVtYWlsIjoiYWRtaW5AbG9jYWxob3N0IiwiZXhwIjoxNzUzNzk1NDM5LCJpYXQiOjE3NTM3OTQ4MzksImlkZW50aWZpZXIiOiJlZWd3MmQxeWtqeTgwYyIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6MzAwMC8iLCJuYW1lc3BhY2UiOiJkZWZhdWx0Iiwic3ViIjoidXNlcjoxIiwidHlwZSI6InVzZXIiLCJ1c2VybmFtZSI6ImFkbWluIn0.Fwngf2bZvQCa9b0kBNZ13WFTVJU7WJrfh2uc1diPd18cDrTYcd_PsLe42aStGUofV1S1GB5vaN3K_TNR-q-PPw', 'x-grafana-org-id': '1', 'accept-encoding': 'gzip'} {} with auth=True
There must be some magic changes with content-length and labels.
First of all, we are should add label_name=label_value to each query
Secondly, we should recalculate the content_length
"""


@app.api_route(
    "/{receiver_name}/{full_path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
)
async def proxy_to_prometheus(
    request: Request,
    receiver_name: str = Path(...),
    full_path: str = Path(...),
    credentials: Optional[HTTPBasicCredentials] = Depends(
        optional_credentials
    ),
):

    # check does receiver exists
    receiver = receiver_map.get(receiver_name)
    if not receiver:
        raise HTTPException(
            status_code=404, detail=f"Receiver '{receiver_name}' not found"
        )

    # check does proxy endpoint should be private
    routines.check_proxy_auth(receiver, credentials)

    base_url = receiver["prom"].rstrip("/")
    url = f"{base_url}/{full_path}"

    # check does receiver should be private (vmauth etc)
    prom_auth = routines.get_prom_auth(receiver, credentials)

    method = request.method
    body = await request.body()

    headers = dict(request.headers)
    headers.pop("host", None)

    # creating proxy client
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            # gathering filtering label pair
            label_name = receiver.get("label_name")
            label_value = receiver.get("label")
            label_pair = (label_name, label_value)
            logger.info(f"Using label pair {label_name, label_value}")

            # gathering query params from client (ie grafana request)
            params = dict(request.query_params)
            modified_body = body

            # modifying POST application/x-www-form-urlencoded
            if routines.should_modify_request(request):
                form = await request.body()
                parsed = parse_qs(form.decode())
                if "query" in parsed:
                    original_query = parsed["query"][0]
                    modified_query = routines.inject_labels(
                        original_query, label_pair
                    )
                    parsed["query"][0] = modified_query

                    modified_body = urlencode(parsed, doseq=True).encode()
                    content_length = str(len(modified_body))
                    headers["content-length"] = content_length
                    body = modified_body

                    logger.info("Modified form body: %s", modified_body)
            # if not form-urlencoded — processing query_params as it is
            elif label_name and label_value:
                params = routines.patch_promql_params(
                    params, label_name, label_value, full_path
                )

            resp = await client.request(
                method=method,
                url=url,
                content=modified_body,
                headers=headers,
                auth=prom_auth,
                params=params,
            )
            logger.info(
                f"Request: {method} {url} {body} {headers} {params} with auth={prom_auth is not None}"
            )
        except httpx.RequestError as e:
            logger.error(f"Proxy request error: {e}")
            raise HTTPException(status_code=502, detail="Bad Gateway")

    excluded_headers = {
        "content-encoding",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
        "content-length",
    }
    headers_to_send = [
        (k, v)
        for k, v in resp.headers.items()
        if k.lower() not in excluded_headers
    ]
    logging.info(f"Headers: {headers_to_send}")
    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=dict(headers_to_send),
    )
