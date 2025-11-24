import json
import datetime
import hashlib
import hmac
import requests
from http.server import BaseHTTPRequestHandler

# ================= 配置区域 =================
# 移除这里的 AK/SK，改为动态传入
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

# 修改点 1：增加 access_key 和 secret_key 参数
def call_volcengine(video_url: str, image_url: str, access_key: str, secret_key: str) -> dict:
    query_params = {'Action': 'CVSync2AsyncSubmitTask', 'Version': '2022-08-31'}
    req_query = format_query(query_params)
    
    body_params = {
        "req_key": "jimeng_dream_actor_m1_gen_video_cv",
        "video_url": video_url,
        "image_url": image_url
    }
    body_str = json.dumps(body_params, ensure_ascii=False)

    # 签名逻辑
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
    
    # 修改点 2：使用传入的 secret_key
    signing_key = get_signature_key(secret_key, date_stamp, REGION, SERVICE)
    signature = hmac.new(signing_key, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    
    # 修改点 3：使用传入的 access_key
    auth_header = f'HMAC-SHA256 Credential={access_key}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}'
    
    headers = {
        'X-Date': amz_date,
        'Authorization': auth_header,
        'X-Content-Sha256': payload_hash,
        'Content-Type': 'application/json',
    }
    
    try:
        resp = requests.post(f'{ENDPOINT}?{req_query}', headers=headers, data=body_str, timeout=10)
        # 尝试解析 JSON，如果解析失败则返回文本
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

            # 修改点 4：从 Body 里提取参数
            video_url = body.get('video_url')
            image_url = body.get('image_url')
            ak = body.get('ak') # 对应飞书里的参数名
            sk = body.get('sk') # 对应飞书里的参数名

            # 简单的校验
            if not all([video_url, image_url, ak, sk]):
                return self._send_json(400, {"msg": "Missing parameters (video_url, image_url, ak, sk)"})

            # 修改点 5：调用时传入 AK/SK
            result = call_volcengine(video_url, image_url, ak, sk)
            
            # 提取 task_id
            volc_data = result.get("data", {})
            task_id = None
            
            # 尝试根据火山结构提取 task_id
            # 通常结构是 data -> result -> task_id 或者直接 result -> task_id，需根据实际返回调整
            if isinstance(volc_data, dict):
                if "Result" in volc_data:
                     task_id = volc_data["Result"].get("task_id")
                elif "data" in volc_data:
                     task_id = volc_data["data"].get("task_id")

            resp_body = {
                "code": 0 if result["status_code"] == 200 else 1,
                "msg": "success" if result["status_code"] == 200 else "volcengine error",
                "task_id": task_id,
                "raw_data": volc_data # 调试用
            }
            
            return self._send_json(200, resp_body)

        except Exception as e:
            return self._send_json(500, {"msg": str(e)})

    def _send_json(self, code, data):
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))