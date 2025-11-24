import json
import datetime
import hashlib
import hmac
import requests
from http.server import BaseHTTPRequestHandler

# ================= 配置区域 =================
HOST = 'visual.volcengineapi.com'
REGION = 'cn-north-1'
ENDPOINT = 'https://visual.volcengineapi.com'
SERVICE = 'cv'
# ==========================================

def sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def get_signature_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = sign(secret_key.encode('utf-8'), date_stamp)
    k_region = sign(k_date, region)
    k_service = sign(k_region, service)
    k_signing = sign(k_service, 'request')
    return k_signing

def format_query(params: dict) -> str:
    return '&'.join(f'{k}={params[k]}' for k in sorted(params))

def call_volcengine(video_url: str, image_url: str, access_key: str, secret_key: str) -> dict:
    query_params = {'Action': 'CVSync2AsyncSubmitTask', 'Version': '2022-08-31'}
    req_query = format_query(query_params)
    
    body_params = {
        "req_key": "jimeng_dream_actor_m1_gen_video_cv",
        "video_url": video_url,
        "image_url": image_url
    }
    body_str = json.dumps(body_params, ensure_ascii=False)

    method = 'POST'
    now = datetime.datetime.utcnow()
    amz_date = now.strftime('%Y%m%dT%H%M%SZ')
    date_stamp = now.strftime('%Y%m%d')
    
    payload_hash = hashlib.sha256(body_str.encode('utf-8')).hexdigest()
    canonical_headers = f'content-type:application/json\nhost:{HOST}\nx-content-sha256:{payload_hash}\nx-date:{amz_date}\n'
    signed_headers = 'content-type;host;x-content-sha256;x-date'
    canonical_request = f'{method}\n/\n{req_query}\n{canonical_headers}\n{signed_headers}\n{payload_hash}'
    
    credential_scope = f'{date_stamp}/{REGION}/{SERVICE}/request'
    string_to_sign = f'HMAC-SHA256\n{amz_date}\n{credential_scope}\n{hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()}'
    
    signing_key = get_signature_key(secret_key, date_stamp, REGION, SERVICE)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    
    auth_header = f'HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}'
    
    headers = {
        'X-Date': amz_date,
        'Authorization': auth_header,
        'X-Content-Sha256': payload_hash,
        'Content-Type': 'application/json',
    }
    
    try:
        resp = requests.post(f'{ENDPOINT}?{req_query}', headers=headers, data=body_str, timeout=10)
        try:
            return {"status_code": resp.status_code, "data": resp.json()}
        except:
            return {"status_code": resp.status_code, "data": {"raw": resp.text}}
    except Exception as e:
        return {"status_code": 500, "data": {"error": str(e)}}

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            raw_body = self.rfile.read(content_length)
            body = json.loads(raw_body.decode('utf-8'))

            video_url = body.get('video_url')
            image_url = body.get('image_url')
            ak = body.get('ak')
            sk = body.get('sk')

            if not all([video_url, image_url, ak, sk]):
                return self._send_json(400, {"msg": "Missing parameters"})

            # 调用火山
            result = call_volcengine(video_url, image_url, ak, sk)
            volc_json = result.get("data", {})
            
            # ==========================================
            # ⭐ 核心解析逻辑修复 (针对你的返回结构)
            # ==========================================
            task_id = None
            
            # 优先检查：{"data": {"task_id": "xxx"}} 结构
            if isinstance(volc_json, dict) and "data" in volc_json:
                data_obj = volc_json["data"]
                # 确保 data 也是个字典，才能去取里面的 key
                if isinstance(data_obj, dict):
                    task_id = data_obj.get("task_id")
            
            # 备用检查：{"Result": {"task_id": "xxx"}} (兼容其他火山接口)
            if not task_id and "Result" in volc_json:
                 task_id = volc_json["Result"].get("task_id")

            # 判断业务是否真正成功
            # HTTP 200 且 成功拿到了 task_id 才算成功
            is_success = (result["status_code"] == 200) and (task_id is not None)

            resp_body = {
                "code": 0 if is_success else 1,
                "msg": "success" if is_success else "failed to get task_id",
                "task_id": task_id,       # 这里是飞书要抓取的关键
                "volc_full_response": volc_json # 把火山原始返回也带上，方便你核对
            }
            
            return self._send_json(200, resp_body)

        except Exception as e:
            return self._send_json(500, {"msg": str(e)})

    def _send_json(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))