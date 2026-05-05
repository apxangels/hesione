from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import Optional
from fastapi import HTTPException, Request
import promql_parser
import urllib.parse
import re

import logging

logger = logging.getLogger(__name__)

"""
inect_labels is query modificator:
 - we shouldnt change queries like 1+1 or smth, let them be executable
 - we must change labels into {} queries
"""

def upsert_matcher(matchers, name, value):
    for m in matchers:
        if m.name == name:
            m.value = value
            m.op = promql_parser.MatchOp.Equal
            return

    matchers.append(
        promql_parser.Matcher(
            name=name,
            value=value,
            op=promql_parser.MatchOp.Equal
        )
    )

def inject_labels_ast(query: str, labels: dict[str, str]) -> str:
    try:
        expr = promql_parser.parse(query)

        def walk(node):

            if isinstance(node, promql_parser.VectorSelector):
                for k, v in labels.items():
                    upsert_matcher(node.matchers.matchers, k, v)

            if not hasattr(node, "__dict__"):
                return

            for attr in vars(node).values():
                if isinstance(attr, list):
                    for item in attr:
                        if hasattr(item, "__dict__"):
                            walk(item)
                elif hasattr(attr, "__dict__"):
                    walk(attr)

        walk(expr)

        result = expr.prettify()
        logger.info("AST result: %s", result)

        return result

    except Exception as e:
        logger.warning("AST inject failed: %s", e)
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
            params["query"] = inject_labels_ast(params["query"], labels)
    elif full_path.endswith("/series"):
        match_keys = [k for k in params if k == "match[]"]

        for k in match_keys:
            values = (
                params.getlist(k) if hasattr(params, "getlist") else params[k]
            )

            if isinstance(values, str):
                values = [values]

            new_values = [
                inject_labels_ast(q, labels) for q in values
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