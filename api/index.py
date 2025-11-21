import json
import datetime
import hashlib
import hmac
import requests
from http.server import BaseHTTPRequestHandler

# =================配置区域=================
# 你要求的：密钥固定在代码里
ACCESS_KEY = 'AKLTNDgyYmRkM2MzZTc2NDhkYTgyMGM0OWVlZmRkNWI4YTY'
SECRET_KEY = 'WW1Zell6VTRNRFl4Tm1JeE5EUXlPRGt4WVdKbU9UWTBPVFF4TWprNE5HRQ=='

HOST = 'visual.volcengineapi.com'
REGION = 'cn-north-1'
ENDPOINT = 'https://visual.volcengineapi.com'
SERVICE = 'cv'
# =========================================

def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()

def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign(key.encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'request')
    return kSigning

def formatQuery(parameters):
    request_parameters_init = ''
    for key in sorted(parameters):
        request_parameters_init += key + '=' + parameters[key] + '&'
    return request_parameters_init[:-1]

def call_volcengine(video_url, image_url):
    # 构造 Query
    query_params = {
        'Action': 'CVSync2AsyncSubmitTask',
        'Version': '2022-08-31',
    }
    req_query = formatQuery(query_params)

    # 构造 Body
    body_params = {
        "req_key": "jimeng_dream_actor_m1_gen_video_cv",
        "video_url": video_url,
        "image_url": image_url
    }
    req_body = json.dumps(body_params)

    # 签名流程 (AWS Signature V4)
    method = 'POST'
    t = datetime.datetime.utcnow()
    current_date = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')
    
    canonical_uri = '/'
    canonical_querystring = req_query
    signed_headers = 'content-type;host;x-content-sha256;x-date'
    payload_hash = hashlib.sha256(req_body.encode('utf-8')).hexdigest()
    content_type = 'application/json'
    
    canonical_headers = 'content-type:' + content_type + '\n' + 'host:' + HOST + \
                        '\n' + 'x-content-sha256:' + payload_hash + \
                        '\n' + 'x-date:' + current_date + '\n'
    
    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + \
                        '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash
    
    algorithm = 'HMAC-SHA256'
    credential_scope = datestamp + '/' + REGION + '/' + SERVICE + '/' + 'request'
    string_to_sign = algorithm + '\n' + current_date + '\n' + credential_scope + '\n' + hashlib.sha256(
        canonical_request.encode('utf-8')).hexdigest()
    
    signing_key = getSignatureKey(SECRET_KEY, datestamp, REGION, SERVICE)
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()
    
    authorization_header = algorithm + ' ' + 'Credential=' + ACCESS_KEY + '/' + \
                           credential_scope + ', ' + 'SignedHeaders=' + \
                           signed_headers + ', ' + 'Signature=' + signature
                           
    headers = {
        'X-Date': current_date,
        'Authorization': authorization_header,
        'X-Content-Sha256': payload_hash,
        'Content-Type': content_type
    }
    
    request_url = ENDPOINT + '?' + req_query
    
    try:
        # 发起请求
        r = requests.post(request_url, headers=headers, data=req_body)
        # 返回结果
        try:
            return r.json(), r.status_code
        except:
            return {"raw_response": r.text}, r.status_code
    except Exception as e:
        return {"error": str(e)}, 500

# Vercel 的入口 Handler
class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            # 1. 获取请求长度
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                 self.send_error_response(400, "Empty body")
                 return

            # 2. 读取飞书发来的数据
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            # 3. 提取字段 (这里需要根据飞书多维表格里你定义的参数名来)
            # 假设飞书发过来的 JSON 里有 video_url 和 image_url 字段
            v_url = data.get('video_url')
            i_url = data.get('image_url')

            if not v_url or not i_url:
                self.send_error_response(400, "Missing video_url or image_url in request body")
                return

            # 4. 调用火山引擎
            result, status_code = call_volcengine(v_url, i_url)

            # 5. 返回结果给飞书
            self.send_response(status_code)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode('utf-8'))

        except Exception as e:
            self.send_error_response(500, str(e))

    def send_error_response(self, code, message):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({"error": message}).encode('utf-8'))