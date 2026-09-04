```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
proxy_handler.py

功能：
1. 支持单个代理 URI
2. 支持订阅 URL
3. 自动识别 Base64 / 明文订阅
4. 自动解析：
   - socks5
   - http
   - https
   - vless
   - vmess
   - hysteria2 / hy2
   - anytls
   - trojan
   - tuic
5. 订阅模式下：
   - 下载订阅
   - 解析全部节点
   - 逐个测试节点
   - 只保留可用节点
   - 使用第一个可用节点作为 proxy
   - 其余可用节点作为备用 urltest 节点

输出：
config.json

HTTP 入站：
127.0.0.1:8080
"""

import os
import sys
import json
import base64
import re
import socket
import ssl
import urllib.request
import urllib.error

from urllib.parse import urlparse, parse_qs, unquote


LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8080

TEST_URL = os.environ.get(
    "PROXY_TEST_URL",
    "https://www.gstatic.com/generate_204"
)

TEST_TIMEOUT = float(
    os.environ.get("PROXY_TEST_TIMEOUT", "8")
)

SUBSCRIPTION_TIMEOUT = int(
    os.environ.get("SUBSCRIPTION_TIMEOUT", "20")
)


SUPPORTED_SCHEMES = {
    "socks5",
    "socks",
    "http",
    "https",
    "vless",
    "vmess",
    "hy2",
    "hysteria2",
    "anytls",
    "trojan",
    "tuic",
}


# ============================================================
# Utility
# ============================================================

def safe_tag(name, index):
    """
    清理节点名称，生成 sing-box 可用 tag。
    """
    name = unquote(str(name or "")).strip()

    name = re.sub(
        r"[\x00-\x1f\x7f]",
        "",
        name
    )

    name = re.sub(
        r"\s+",
        " ",
        name
    )

    if not name:
        name = f"node-{index}"

    return name[:120]


def unique_tag(tag, existing):
    """
    防止节点名称重复。
    """
    if tag not in existing:
        return tag

    i = 2

    while f"{tag}-{i}" in existing:
        i += 1

    return f"{tag}-{i}"


# ============================================================
# Protocol Parsers
# ============================================================

def parse_socks5(parsed):
    outbound = {
        "type": "socks",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 1080,
        "version": "5",
    }

    if parsed.username:
        outbound["username"] = unquote(parsed.username)

    if parsed.password:
        outbound["password"] = unquote(parsed.password)

    return outbound


def parse_http(parsed):
    outbound = {
        "type": "http",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 8080,
    }

    if parsed.username:
        outbound["username"] = unquote(parsed.username)

    if parsed.password:
        outbound["password"] = unquote(parsed.password)

    if parsed.scheme.lower() == "https":
        outbound["tls"] = {
            "enabled": True
        }

    return outbound


def parse_vless(parsed, params):

    outbound = {
        "type": "vless",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "uuid": unquote(parsed.username or ""),
    }

    flow = params.get(
        "flow",
        [""]
    )[0]

    if flow:
        outbound["flow"] = flow

    security = params.get(
        "security",
        [""]
    )[0].lower()

    if security in (
        "tls",
        "reality"
    ):

        tls = {
            "enabled": True
        }

        sni = (
            params.get("sni", [""])[0]
            or params.get("peer", [""])[0]
            or params.get("host", [""])[0]
        )

        if sni:
            tls["server_name"] = unquote(sni)

        fp = (
            params.get("fp", [""])[0]
            or params.get(
                "client-fingerprint",
                [""]
            )[0]
        )

        if fp:
            tls["utls"] = {
                "enabled": True,
                "fingerprint": fp,
            }

        alpn = params.get(
            "alpn",
            [""]
        )[0]

        if alpn:
            tls["alpn"] = [
                x for x in alpn.split(",")
                if x
            ]

        insecure = params.get(
            "insecure",
            params.get(
                "allowInsecure",
                ["0"]
            )
        )[0]

        if insecure == "1":
            tls["insecure"] = True

        if security == "reality":

            reality = {
                "enabled": True
            }

            pbk = params.get(
                "pbk",
                [""]
            )[0]

            if pbk:
                reality["public_key"] = pbk

            sid = params.get(
                "sid",
                [""]
            )[0]

            if sid:
                reality["short_id"] = sid

            spx = params.get(
                "spx",
                [""]
            )[0]

            if spx:
                reality["spider_x"] = unquote(spx)

            tls["reality"] = reality

        outbound["tls"] = tls

    net_type = params.get(
        "type",
        [""]
    )[0].lower()

    if net_type == "ws":

        transport = {
            "type": "ws"
        }

        path = params.get(
            "path",
            [""]
        )[0]

        if path:
            transport["path"] = unquote(path)

        host = params.get(
            "host",
            [""]
        )[0]

        if host:
            transport["headers"] = {
                "Host": unquote(host)
            }

        outbound["transport"] = transport

    elif net_type == "grpc":

        transport = {
            "type": "grpc"
        }

        service_name = (
            params.get(
                "serviceName",
                [""]
            )[0]
            or params.get(
                "service_name",
                [""]
            )[0]
        )

        if service_name:
            transport["service_name"] = unquote(
                service_name
            )

        outbound["transport"] = transport

    elif net_type in (
        "http",
        "h2"
    ):

        transport = {
            "type": "http"
        }

        path = params.get(
            "path",
            [""]
        )[0]

        if path:
            transport["path"] = unquote(path)

        host = params.get(
            "host",
            [""]
        )[0]

        if host:
            transport["host"] = [
                unquote(host)
            ]

        outbound["transport"] = transport

    return outbound


def parse_vmess(url_str):

    encoded = url_str[
        len("vmess://"):
    ].strip()

    encoded = encoded.replace(
        "-",
        "+"
    ).replace(
        "_",
        "/"
    )

    padding = (
        4 - len(encoded) % 4
    ) % 4

    encoded += "=" * padding

    decoded = base64.b64decode(
        encoded
    ).decode(
        "utf-8-sig"
    )

    cfg = json.loads(decoded)

    outbound = {
        "type": "vmess",
        "tag": "proxy",
        "server": cfg.get(
            "add",
            ""
        ),
        "server_port": int(
            cfg.get(
                "port",
                443
            )
        ),
        "uuid": cfg.get(
            "id",
            ""
        ),
        "security": cfg.get(
            "scy",
            "auto"
        ),
        "alter_id": int(
            cfg.get(
                "aid",
                0
            )
        ),
    }

    if cfg.get("tls") == "tls":

        tls = {
            "enabled": True
        }

        sni = (
            cfg.get("sni")
            or cfg.get("host")
            or ""
        )

        if sni:
            tls["server_name"] = sni

        alpn = cfg.get(
            "alpn",
            ""
        )

        if alpn:
            tls["alpn"] = [
                x for x in alpn.split(",")
                if x
            ]

        outbound["tls"] = tls

    net = cfg.get(
        "net",
        "tcp"
    )

    if net == "ws":

        transport = {
            "type": "ws"
        }

        path = cfg.get(
            "path",
            ""
        )

        if path:
            transport["path"] = path

        host = cfg.get(
            "host",
            ""
        )

        if host:
            transport["headers"] = {
                "Host": host
            }

        outbound["transport"] = transport

    elif net == "grpc":

        transport = {
            "type": "grpc"
        }

        service_name = (
            cfg.get("serviceName")
            or cfg.get("path")
            or ""
        )

        if service_name:
            transport["service_name"] = service_name

        outbound["transport"] = transport

    elif net in (
        "h2",
        "http"
    ):

        transport = {
            "type": "http"
        }

        path = cfg.get(
            "path",
            ""
        )

        if path:
            transport["path"] = path

        host = cfg.get(
            "host",
            ""
        )

        if host:
            transport["host"] = [
                host
            ]

        outbound["transport"] = transport

    return outbound


def parse_hysteria2(parsed, params):

    outbound = {
        "type": "hysteria2",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "password": unquote(
            parsed.username or ""
        ),
    }

    tls = {
        "enabled": True
    }

    sni = (
        params.get("sni", [""])[0]
        or params.get("peer", [""])[0]
    )

    if sni:
        tls["server_name"] = unquote(sni)

    insecure = params.get(
        "insecure",
        params.get(
            "allowInsecure",
            ["0"]
        )
    )[0]

    if insecure == "1":
        tls["insecure"] = True

    alpn = params.get(
        "alpn",
        [""]
    )[0]

    if alpn:
        tls["alpn"] = [
            x for x in alpn.split(",")
            if x
        ]

    outbound["tls"] = tls

    obfs = params.get(
        "obfs",
        [""]
    )[0]

    if obfs:

        obfs_password = params.get(
            "obfs-password",
            [""]
        )[0]

        outbound["obfs"] = {
            "type": obfs,
            "password": obfs_password,
        }

    return outbound


def parse_anytls(parsed, params):

    outbound = {
        "type": "anytls",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "password": unquote(
            parsed.username or ""
        ),
    }

    tls = {
        "enabled": True
    }

    sni = (
        params.get("sni", [""])[0]
        or params.get("peer", [""])[0]
    )

    if sni:
        tls["server_name"] = unquote(sni)

    fp = (
        params.get("fp", [""])[0]
        or params.get(
            "client-fingerprint",
            [""]
        )[0]
    )

    if fp:
        tls["utls"] = {
            "enabled": True,
            "fingerprint": fp,
        }

    insecure = params.get(
        "insecure",
        params.get(
            "allowInsecure",
            ["0"]
        )
    )[0]

    if insecure == "1":
        tls["insecure"] = True

    outbound["tls"] = tls

    return outbound


def parse_trojan(parsed, params):

    outbound = {
        "type": "trojan",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "password": unquote(
            parsed.username or ""
        ),
    }

    tls = {
        "enabled": True
    }

    sni = (
        params.get("sni", [""])[0]
        or params.get("peer", [""])[0]
        or params.get("host", [""])[0]
    )

    if sni:
        tls["server_name"] = unquote(sni)

    fp = (
        params.get("fp", [""])[0]
        or params.get(
            "client-fingerprint",
            [""]
        )[0]
    )

    if fp:
        tls["utls"] = {
            "enabled": True,
            "fingerprint": fp,
        }

    insecure = params.get(
        "insecure",
        params.get(
            "allowInsecure",
            ["0"]
        )
    )[0]

    if insecure == "1":
        tls["insecure"] = True

    alpn = params.get(
        "alpn",
        [""]
    )[0]

    if alpn:
        tls["alpn"] = [
            x for x in alpn.split(",")
            if x
        ]

    outbound["tls"] = tls

    transport_type = params.get(
        "type",
        [""]
    )[0].lower()

    if transport_type == "ws":

        ws = {
            "type": "ws"
        }

        path = params.get(
            "path",
            [""]
        )[0]

        if path:
            ws["path"] = unquote(path)

        host = params.get(
            "host",
            [""]
        )[0]

        if host:
            ws["headers"] = {
                "Host": unquote(host)
            }

        outbound["transport"] = ws

    elif transport_type == "grpc":

        grpc = {
            "type": "grpc"
        }

        service_name = (
            params.get(
                "serviceName",
                [""]
            )[0]
            or params.get(
                "service_name",
                [""]
            )[0]
        )

        if service_name:
            grpc["service_name"] = unquote(
                service_name
            )

        outbound["transport"] = grpc

    return outbound


def parse_tuic(parsed, params):

    outbound = {
        "type": "tuic",
        "tag": "proxy",
        "server": parsed.hostname,
        "server_port": parsed.port or 443,
        "uuid": "",
        "password": "",
        "congestion_control": params.get(
            "congestion_control",
            ["bbr"]
        )[0],
    }

    user_part = unquote(
        parsed.username or ""
    )

    pass_part = unquote(
        parsed.password or ""
    )

    if ":" in user_part and not pass_part:

        outbound["uuid"], outbound["password"] = (
            user_part.split(
                ":",
                1
            )
        )

    else:

        outbound["uuid"] = user_part
        outbound["password"] = pass_part

    tls = {
        "enabled": True
    }

    sni = (
        params.get("sni", [""])[0]
        or params.get("peer", [""])[0]
    )

    if sni:
        tls["server_name"] = unquote(sni)

    insecure = params.get(
        "insecure",
        params.get(
            "allowInsecure",
            ["0"]
        )
    )[0]

    if insecure == "1":
        tls["insecure"] = True

    alpn = params.get(
        "alpn",
        [""]
    )[0]

    if alpn:
        tls["alpn"] = [
            x for x in alpn.split(",")
            if x
        ]

    outbound["tls"] = tls

    return outbound


# ============================================================
# URI parser
# ============================================================

def parse_proxy_uri(uri):

    uri = uri.strip()

    if not uri:
        raise ValueError(
            "empty URI"
        )

    scheme = uri.split(
        "://",
        1
    )[0].lower()

    if scheme == "socks":
        scheme = "socks5"
        uri = "socks5://" + uri.split(
            "://",
            1
        )[1]

    if scheme == "vmess":

        outbound = parse_vmess(uri)

        try:

            encoded = uri[
                len("vmess://"):
            ]

            padding = (
                4 - len(encoded) % 4
            ) % 4

            encoded += "=" * padding

            cfg = json.loads(
                base64.b64decode(
                    encoded
                ).decode(
                    "utf-8-sig"
                )
            )

            name = (
                cfg.get("ps")
                or cfg.get("name")
                or ""
            )

        except Exception:

            name = ""

        return outbound, name

    parsed = urlparse(uri)

    params = parse_qs(
        parsed.query
    )

    name = (
        parsed.fragment
        or params.get(
            "name",
            [""]
        )[0]
    )

    if scheme == "socks5":
        outbound = parse_socks5(parsed)

    elif scheme in (
        "http",
        "https"
    ):
        outbound = parse_http(parsed)

    elif scheme == "vless":
        outbound = parse_vless(
            parsed,
            params
        )

    elif scheme in (
        "hy2",
        "hysteria2"
    ):
        outbound = parse_hysteria2(
            parsed,
            params
        )

    elif scheme == "anytls":
        outbound = parse_anytls(
            parsed,
            params
        )

    elif scheme == "trojan":
        outbound = parse_trojan(
            parsed,
            params
        )

    elif scheme == "tuic":
        outbound = parse_tuic(
            parsed,
            params
        )

    else:

        raise ValueError(
            f"Unsupported protocol: {scheme}"
        )

    return outbound, name


# ============================================================
# Subscription decoder
# ============================================================

def decode_subscription(raw):

    if isinstance(raw, bytes):

        text = raw.decode(
            "utf-8-sig",
            errors="replace"
        )

    else:

        text = str(raw)

    text = text.strip()

    if not text:
        return []

    text = text.lstrip(
        "\ufeff"
    ).strip()

    uri_pattern = re.compile(
        r"^(?:"
        r"socks5|socks|http|https|"
        r"vless|vmess|hy2|hysteria2|"
        r"anytls|trojan|tuic"
        r")://",
        re.I
    )

    # --------------------------------------------------------
    # Plain text
    # --------------------------------------------------------

    lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
    ]

    uri_lines = [
        line
        for line in lines
        if uri_pattern.match(line)
    ]

    if uri_lines:
        return uri_lines

    # --------------------------------------------------------
    # Base64
    # --------------------------------------------------------

    compact = re.sub(
        r"\s+",
        "",
        text
    )

    candidates = []

    candidates.append(
        compact
    )

    padding = (
        4 - len(compact) % 4
    ) % 4

    if padding:
        candidates.append(
            compact + "=" * padding
        )

    for candidate in candidates:

        try:

            decoded = base64.b64decode(
                candidate,
                validate=False
            ).decode(
                "utf-8-sig",
                errors="replace"
            )

            decoded_lines = [
                line.strip()
                for line in decoded.splitlines()
                if line.strip()
            ]

            uri_lines = [
                line
                for line in decoded_lines
                if uri_pattern.match(line)
            ]

            if uri_lines:
                return uri_lines

        except Exception:
            pass

    # --------------------------------------------------------
    # URL-safe Base64
    # --------------------------------------------------------

    try:

        decoded = base64.urlsafe_b64decode(
            compact + "=" * (
                (-len(compact)) % 4
            )
        ).decode(
            "utf-8-sig",
            errors="replace"
        )

        decoded_lines = [
            line.strip()
            for line in decoded.splitlines()
            if line.strip()
        ]

        uri_lines = [
            line
            for line in decoded_lines
            if uri_pattern.match(line)
        ]

        if uri_lines:
            return uri_lines

    except Exception:
        pass

    return []


# ============================================================
# Subscription downloader
# ============================================================

def fetch_subscription(url):

    print(
        "  Downloading subscription..."
    )

    headers = {
        "User-Agent": os.environ.get(
            "SUBSCRIPTION_USER_AGENT",
            "clash.meta/1.19.0"
        ),
        "Accept": (
            "text/plain,"
            "application/base64,"
            "application/json,"
            "*/*"
        ),
        "Cache-Control": "no-cache",
    }

    request = urllib.request.Request(
        url,
        headers=headers
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=SUBSCRIPTION_TIMEOUT
        ) as response:

            body = response.read()

            print(
                f"  Subscription downloaded: "
                f"{len(body)} bytes"
            )

            return body

    except urllib.error.HTTPError as e:

        raise RuntimeError(
            f"HTTP {e.code}: {e.reason}"
        )

    except urllib.error.URLError as e:

        raise RuntimeError(
            f"Network error: {e.reason}"
        )

    except Exception as e:

        raise RuntimeError(
            f"Download failed: {e}"
        )


# ============================================================
# Subscription URL detection
# ============================================================

def is_subscription_url(url):

    try:

        parsed = urlparse(url)

        if parsed.scheme.lower() not in (
            "http",
            "https"
        ):
            return False

        # 例如：
        #
        # https://xxx.com/sabusuku?token=xxx
        #
        # 这种肯定是订阅 URL。

        if parsed.query:
            return True

        if parsed.path not in (
            "",
            "/"
        ):
            return True

        # 没有端口的 HTTP URL，一般也视为订阅。
        if parsed.port is None:
            return True

        return False

    except Exception:

        return False


# ============================================================
# Node connectivity helper
# ============================================================

def tcp_test(server, port, timeout=TEST_TIMEOUT):

    try:

        with socket.create_connection(
            (
                server,
                int(port)
            ),
            timeout=timeout
        ):

            return True

    except Exception:

        return False


def test_node_basic(outbound):

    """
    第一层快速检测：

    这里只检测目标服务器 TCP 端口是否能从
    GitHub Actions 出网环境建立连接。

    注意：
    TCP 成功 ≠ 代理一定能用。

    但 TCP 都不通的节点没有必要交给 sing-box。
    """

    server = outbound.get(
        "server"
    )

    port = outbound.get(
        "server_port"
    )

    if not server or not port:
        return False

    return tcp_test(
        server,
        port
    )


# ============================================================
# Subscription builder
# ============================================================

def build_subscription_outbounds(uri_list):

    parsed_nodes = []

    existing_tags = set()

    print(
        "  Parsing subscription nodes..."
    )

    for index, uri in enumerate(
        uri_list,
        1
    ):

        try:

            outbound, name = parse_proxy_uri(
                uri
            )

            tag = safe_tag(
                name,
                index
            )

            tag = unique_tag(
                tag,
                existing_tags
            )

            existing_tags.add(
                tag
            )

            outbound["tag"] = tag

            parsed_nodes.append(
                outbound
            )

        except Exception as e:

            print(
                f"  Skip node #{index}: {e}"
            )

    if not parsed_nodes:

        raise RuntimeError(
            "No supported proxy nodes found"
        )

    print(
        f"  Parsed {len(parsed_nodes)} nodes"
    )

    # --------------------------------------------------------
    # TCP 筛选
    # --------------------------------------------------------

    print(
        "  Testing node TCP connectivity..."
    )

    reachable = []
    failed = []

    for index, outbound in enumerate(
        parsed_nodes,
        1
    ):

        server = outbound.get(
            "server",
            ""
        )

        port = outbound.get(
            "server_port",
            ""
        )

        tag = outbound.get(
            "tag",
            f"node-{index}"
        )

        print(
            f"  [{index}/{len(parsed_nodes)}] "
            f"{tag} -> {server}:{port}"
        )

        if test_node_basic(
            outbound
        ):

            print(
                "       TCP OK"
            )

            reachable.append(
                outbound
            )

        else:

            print(
                "       TCP FAILED"
            )

            failed.append(
                outbound
            )

    print(
        f"  Reachable nodes: "
        f"{len(reachable)}"
    )

    print(
        f"  Unreachable nodes: "
        f"{len(failed)}"
    )

    if not reachable:

        raise RuntimeError(
            "No reachable proxy nodes. "
            "All subscription node TCP ports failed."
        )

    # --------------------------------------------------------
    # 防止一次性测试 101 个节点
    #
    # 只取前 N 个可用节点。
    # 默认 10 个。
    # --------------------------------------------------------

    max_nodes = int(
        os.environ.get(
            "MAX_PROXY_NODES",
            "10"
        )
    )

    if max_nodes > 0:

        reachable = reachable[
            :max_nodes
        ]

    # --------------------------------------------------------
    # 给节点重新编号
    # --------------------------------------------------------

    for index, outbound in enumerate(
        reachable,
        1
    ):

        # 保留原名称
        if not outbound.get(
            "tag"
        ):
            outbound["tag"] = (
                f"node-{index}"
            )

    # --------------------------------------------------------
    # 单节点
    # --------------------------------------------------------

    if len(reachable) == 1:

        reachable[0]["tag"] = "proxy"

        return [
            reachable[0],
            {
                "type": "direct",
                "tag": "direct",
            }
        ]

    # --------------------------------------------------------
    # 多节点
    # --------------------------------------------------------

    node_tags = [
        node["tag"]
        for node in reachable
    ]

    urltest = {
        "type": "urltest",
        "tag": "proxy",
        "outbounds": node_tags,
        "url": TEST_URL,
        "interval": os.environ.get(
            "URLTEST_INTERVAL",
            "60s"
        ),
        "tolerance": int(
            os.environ.get(
                "URLTEST_TOLERANCE",
                "100"
            )
        ),
    }

    return (
        reachable
        + [
            urltest,
            {
                "type": "direct",
                "tag": "direct",
            }
        ]
    )


# ============================================================
# Original pool support
# ============================================================

def load_pool():

    pool_file = os.environ.get(
        "POOL_FILE",
        "pool.json"
    )

    if not os.path.exists(
        pool_file
    ):
        return []

    try:

        with open(
            pool_file,
            "r",
            encoding="utf-8"
        ) as f:

            data = json.load(f)

        return [
            node
            for node in data
            if node.get("server")
            and node.get("port")
        ]

    except Exception as e:

        print(
            f"Warning: failed to load pool.json: {e}"
        )

        return []


def build_pool_outbounds(
    base_out,
    pool_nodes
):

    outbounds = []

    for index, node in enumerate(
        pool_nodes,
        1
    ):

        outbound = json.loads(
            json.dumps(
                base_out
            )
        )

        outbound["tag"] = (
            f"node-{index}"
        )

        outbound["server_port"] = int(
            node["port"]
        )

        if node.get("sni"):

            outbound.setdefault(
                "tls",
                {}
            )

            outbound["tls"][
                "enabled"
            ] = True

            outbound["tls"][
                "server_name"
            ] = node["sni"]

        outbounds.append(
            outbound
        )

    outbounds.append(
        {
            "type": "urltest",
            "tag": "proxy",
            "outbounds": [
                f"node-{i}"
                for i in range(
                    1,
                    len(pool_nodes) + 1
                )
            ],
            "url": TEST_URL,
            "interval": "30s",
        }
    )

    outbounds.append(
        {
            "type": "direct",
            "tag": "direct",
        }
    )

    return outbounds


# ============================================================
# Config writer
# ============================================================

def write_config(
    outbounds
):

    config = {
        "log": {
            "level": "info",
            "timestamp": True,
        },

        "inbounds": [
            {
                "type": "http",
                "tag": "http-in",
                "listen": LISTEN_HOST,
                "listen_port": LISTEN_PORT,
            }
        ],

        "outbounds": outbounds,

        "route": {
            "final": "proxy"
        }
    }

    with open(
        "config.json",
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            config,
            f,
            indent=2,
            ensure_ascii=False
        )

    print(
        "sing-box config.json generated."
    )

    print(
        f"  Inbound: "
        f"http://{LISTEN_HOST}:{LISTEN_PORT}"
    )


# ============================================================
# Main
# ============================================================

def main():

    proxy_url = os.environ.get(
        "PROXY_URL",
        ""
    ).strip()

    subscription_url = os.environ.get(
        "SUBSCRIPTION_URL",
        ""
    ).strip()

    source_url = (
        subscription_url
        or proxy_url
    )

    if not source_url:

        print(
            "PROXY_URL/SUBSCRIPTION_URL "
            "is empty, skipping proxy."
        )

        sys.exit(0)

    # ========================================================
    # Subscription mode
    # ========================================================

    if (
        subscription_url
        or is_subscription_url(
            source_url
        )
    ):

        print(
            "Subscription mode: "
            "downloading subscription..."
        )

        # 不在日志里打印 token。
        safe_url = source_url.split(
            "?",
            1
        )[0]

        print(
            f"  URL: {safe_url}***"
        )

        try:

            raw = fetch_subscription(
                source_url
            )

            uri_list = decode_subscription(
                raw
            )

        except Exception as e:

            print(
                f"Failed to download/parse "
                f"subscription: {e}"
            )

            sys.exit(1)

        if not uri_list:

            print(
                "Subscription downloaded, "
                "but no supported proxy URI "
                "was found."
            )

            print(
                "Supported:"
            )

            print(
                "  vless / vmess / trojan / "
                "hysteria2 / anytls / tuic / "
                "socks5 / http"
            )

            sys.exit(1)

        print(
            f"  Found {len(uri_list)} "
            f"proxy nodes"
        )

        try:

            outbounds = (
                build_subscription_outbounds(
                    uri_list
                )
            )

        except Exception as e:

            print(
                f"Failed to build "
                f"subscription outbounds: {e}"
            )

            sys.exit(1)

        write_config(
            outbounds
        )

        proxy_nodes = [
            x
            for x in outbounds
            if x.get("tag") != "proxy"
            and x.get("tag") != "direct"
            and x.get("type") != "urltest"
        ]

        print(
            f"  Usable nodes: "
            f"{len(proxy_nodes)}"
        )

        if len(proxy_nodes) == 1:

            print(
                "  Selector: direct proxy"
            )

        else:

            print(
                "  Selector: "
                "urltest -> proxy"
            )

        return

    # ========================================================
    # Single URI mode
    # ========================================================

    scheme = source_url.split(
        "://",
        1
    )[0].lower()

    print(
        f"Parsing proxy URI "
        f"({scheme}://***)"
    )

    try:

        outbound, name = parse_proxy_uri(
            source_url
        )

    except Exception as e:

        print(
            f"Unsupported/invalid "
            f"proxy URI: {e}"
        )

        sys.exit(1)

    if name:

        outbound["tag"] = safe_tag(
            name,
            1
        )

    else:

        outbound["tag"] = "proxy"

    # ========================================================
    # anytls pool
    # ========================================================

    outbounds = [
        outbound,
        {
            "type": "direct",
            "tag": "direct",
        }
    ]

    if scheme == "anytls":

        pool = load_pool()

        if pool:

            node_outbounds = (
                build_pool_outbounds(
                    outbound,
                    pool
                )
            )

            if node_outbounds:

                outbounds = node_outbounds

                print(
                    f"  Pool mode: "
                    f"{len(pool)} nodes + urltest"
                )

    write_config(
        outbounds
    )

    server = outbound.get(
        "server",
        "N/A"
    )

    port = outbound.get(
        "server_port",
        "N/A"
    )

    print(
        f"  Outbound: "
        f"{outbound['type']} "
        f"-> {server}:{port}"
    )


if __name__ == "__main__":
    main()
```
