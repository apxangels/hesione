from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Optional
from fastapi import HTTPException, Request
import urllib.parse
import re

import logging

logger = logging.getLogger(__name__)

"""
inect_labels is query modificator:
 - we shouldnt change queries like 1+1 or smth, let them be executable
 - we must change labels into {} queries
"""


def inject_labels(query: str, labels: dict[str, str]) -> str:
    try:
        expr = query.strip()

        if expr in ("", "1", "1+1", "vector(1)"):
            return expr

        def format_labels(lbls: dict):
            return ",".join(f'{k}="{v}"' for k, v in lbls.items())

        pattern = re.compile(r"(\{[^}]*\})")

        if "{" in expr:
            def add_labels(match):
                content = match.group(1).strip("{}")

                existing = {}
                if content:
                    for l in content.split(","):
                        k, v = l.split("=", 1)
                        existing[k] = v.strip('"')

                # override / merge
                for k, v in labels.items():
                    existing[k] = f'"{v}"'

                return "{" + ",".join(f"{k}={v}" for k, v in existing.items()) + "}"

            return pattern.sub(add_labels, expr)

        else:
            return f"{expr}{{{format_labels(labels)}}}"

    except Exception as e:
        logger.warning("Failed to inject labels into query: %s", e)
        return query

def check_proxy_auth(
    receiver: dict, credentials: Optional[HTTPBasicCredentials]
):
    auth_cfg = receiver.get("auth")
    receiver_name = receiver.get("name")
    logger.info(f"Gather proxy credentials {auth_cfg} for {receiver_name}")

    if not auth_cfg:
        logger.info("no auth provided for receiver")
        return

    if auth_cfg == "preserve":
        prom_auth = receiver.get("prom_auth")
        logger.info(
            f"Gather proxy auth from prom_auth with preserve {prom_auth}"
        )
        if not prom_auth:
            return
        expected_user = prom_auth.get("user")
        expected_pass = prom_auth.get("password")
        logger.info(
            f"Gather proxy auth from config {expected_user}, {expected_pass}"
        )
        if (
            not credentials
            or credentials.username != expected_user
            or credentials.password != expected_pass
        ):
            raise HTTPException(status_code=401, detail="Unauthorized")
            logger.error(
                f"Gather {credentials.username}:{credentials.password} for {expected_user}:{expected_pass}"
            )
    else:
        expected_user = auth_cfg.get("user")
        expected_pass = auth_cfg.get("password")
        logger.info(
            f"Gather proxy auth from config {expected_user}, {expected_pass}"
        )
        if (
            not credentials
            or credentials.username != expected_user
            or credentials.password != expected_pass
        ):
            raise HTTPException(status_code=401, detail="Unauthorized")
            logger.error(
                f"Gather {credentials.username}:{credentials.password} for {expected_user}:{expected_pass}"
            )


def get_prom_auth(
    receiver: dict, request_credentials: Optional[HTTPBasicCredentials]
) -> Optional[tuple]:
    auth_cfg = receiver.get("auth")
    prom_auth = receiver.get("prom_auth")

    if auth_cfg == "preserve":
        if request_credentials:
            return (request_credentials.username, request_credentials.password)
        if prom_auth:
            return (prom_auth.get("user"), prom_auth.get("password"))
        return None

    if prom_auth:
        return (prom_auth.get("user"), prom_auth.get("password"))
    return None


def patch_promql_params(params: dict, labels: dict, full_path: str) -> dict:
    if full_path.endswith("/query") or full_path.endswith("/query_range"):
        if "query" in params:
            params = dict(params)
            params["query"] = inject_labels(params["query"], labels)

    elif full_path.endswith("/series"):
        match_keys = [k for k in params if k == "match[]"]

        for k in match_keys:
            values = (
                params.getlist(k) if hasattr(params, "getlist") else params[k]
            )

            if isinstance(values, str):
                values = [values]

            new_values = [
                inject_labels(q, labels) for q in values
            ]

            params = dict(params)
            params[k] = new_values

    return params


# Which requests should be overwrite
def should_modify_request(request: Request) -> bool:
    if request.method != "POST":
        return False

    if not request.headers.get("content-type", "").startswith(
        "application/x-www-form-urlencoded"
    ):
        return False

    # Только специфичные endpoint'ы
    allowed_paths = [
        "/prometheus/api/v1/query_range",
        "/prometheus/api/v1/query",
        "/api/v1/query_range",
        "/api/v1/query",
    ]
    return any(request.url.path.endswith(p) for p in allowed_paths)
# return (verify, cert) for httpx
def get_backend_ssl_params(receiver: dict):

    verify = receiver.get("verify", True)

    if "cert" in receiver and "key" in receiver:
        cert = (receiver["cert"], receiver["key"])
    else:
        cert = None

    return verify, cert