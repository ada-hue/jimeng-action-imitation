import json
import datetime
import hashlib
import hmac
import requests
from http.server import BaseHTTPRequestHandler

# ================= 配置区域 =================
ACCESS_KEY = 'AKLTNDgyYmRkM2MzZTc2NDhkYTgyMGM0OWVlZmRkNWI4YTY'
SECRET_KEY = 'WW1Zell6VTRNRFl4Tm1JeE5EUXlPRGt4WVdKbU9UWTBPVFF4TWprNE5HRQ=='

HOST = 'visual.volcengineapi.com'
REGION = 'cn-north-1'
ENDPOINT = 'https://visual.volcengineapi.com'
SERVICE = 'cv'
# ==========================================


def sign(key: bytes, msg: str) -> bytes:
    """HMAC-SHA256"""
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def get_signature_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    """生成签名 key（按 volcengine 文档的流程来）"""
    k_date = sign(secret_key.encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, 'request')
    return k_signing


def format_query(params: dict) -> str:
    """把 query dict 按 key 排序后拼成 querystring"""
    return '&'.join(f'{k}={params[k]}' for k in sorted(params))


def call_volcengine(video_url: str, image_url: str, timeout: int = 5) -> dict:
    """调用火山引擎，返回结构化结果"""

    # 1. Query
    query_params = {
        'Action': 'CVSync2AsyncSubmitTask',
        'Version': '2022-08-31',
    }
    req_query = format_query(query_params)

    # 2. Body
    body_params = {
        "req_key": "jimeng_dream_actor_m1_gen_video_cv",
        "video_url": video_url,
        "image_url": image_url
    }
    body_str = json.dumps(body_params, ensure_ascii=False)

    # 3. 签名
    method = 'POST'
    now = datetime.datetime.utcnow()
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = now.strftime('%Y%m%d')

    canonical_uri = '/'
    canonical_querystring = req_query
    content_type = 'application/json'
    payload_hash = hashlib.sha256(body_str.encode('utf-8')).hexdigest()
    signed_headers = 'content-type;host;x-content-sha256;x-date'

    canonical_headers = (
        f'content-type:{content_type}\n'
        f'host:{HOST}\n'
        f'x-content-sha256:{payload_hash}\n'
        f'x-date:{amz_date}\n'
    )

    canonical_request = (
        f'{method}\n'
        f'{canonical_uri}\n'
        f'{canonical_querystring}\n'
        f'{canonical_headers}\n'
        f'{signed_headers}\n'
        f'{payload_hash}'
    )

    algorithm = 'HMAC-SHA256'
    credential_scope = f'{date_stamp}/{REGION}/{SERVICE}/request'
    string_to_sign = (
        f'{algorithm}\n'
        f'{amz_date}\n'
        f'{credential_scope}\n'
        f'{hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()}'
    )

    signing_key = get_signature_key(SECRET_KEY, date_stamp, REGION, SERVICE)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()

    auth_header = (
        f'{algorithm} '
        f'Credential={ACCESS_KEY}/{credential_scope}, '
        f'SignedHeaders={signed_headers}, '
        f'Signature={signature}'
    )

    headers = {
        'X-Date': amz_date,
        'Authorization': auth_header,
        'X-Content-Sha256': payload_hash,
        'Content-Type': content_type,
    }

    url = f'{ENDPOINT}?{req_query}'

    try:
        # ⭐ 关键：加 timeout，避免无限等待拖成飞书超时
        resp = requests.post(url, headers=headers, data=body_str, timeout=timeout)

        try:
            data = resp.json()
        except Exception:
            data = {"raw_response": resp.text}

        return {
            "ok": resp.ok,
            "status": resp.status_code,
            "data": data,
        }

    except requests.exceptions.Timeout:
        return {
            "ok": False,
            "status": 504,
            "data": {"error": "volcengine request timeout"},
        }
    except Exception as e:
        return {
            "ok": False,
            "status": 500,
            "data": {"error": str(e)},
        }


class handler(BaseHTTPRequestHandler):
    """Vercel Python Runtime 入口"""

    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', '0'))
            if content_length <= 0:
                return self._send_json(200, {
                    "code": 1,
                    "msg": "Empty body",
                    "data": None
                })

            raw_body = self.rfile.read(content_length)
            print("feishu raw body:", raw_body)  # 方便在 Vercel Logs 里调试

            try:
                body = json.loads(raw_body.decode('utf-8'))
            except Exception:
                return self._send_json(200, {
                    "code": 1,
                    "msg": "Invalid JSON body",
                    "data": None
                })

            # 从飞书请求里拿视频 / 图片链接
            video_url = body.get('video_url')
            image_url = body.get('image_url')

            if not video_url or not image_url:
                return self._send_json(200, {
                    "code": 1,
                    "msg": "Missing video_url or image_url",
                    "data": body  # 顺便把原始 body 返回方便你排查
                })

            # 调用火山引擎
            volc_result = call_volcengine(video_url, image_url)

            # 统一对飞书返回 200，结果用 code/msg 表示
            resp_body = {
                "code": 0 if volc_result["ok"] else 1,
                "msg": "ok" if volc_result["ok"] else "volcengine error",
                "http_status": volc_result["status"],
                "data": volc_result["data"],
            }

            return self._send_json(200, resp_body)

        except Exception as e:
            print("internal error:", e)
            return self._send_json(200, {
                "code": 1,
                "msg": f"internal error: {e}",
                "data": None
            })

    def do_GET(self):
        """浏览器直接访问 /api 时的简单健康检查"""
        return self._send_json(200, {
            "code": 0,
            "msg": "ok",
            "data": "python function alive"
        })

    def _send_json(self, status_code: int, body: dict):
        self.send_response(status_code)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.end_headers()
        self.wfile.write(json.dumps(body, ensure_ascii=False).encode('utf-8'))
