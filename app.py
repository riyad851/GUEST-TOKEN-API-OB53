import json
import base64
import asyncio
import httpx
from Crypto.Cipher import AES
from flask import Flask, request, jsonify
import logging
from google.protobuf import json_format

# Configure logging for Vercel / local dev
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Attempt to import Protobuf (adjust path if needed)
try:
    from proto import FreeFire_pb2
    logger.info("Successfully imported FreeFire_pb2")
except ImportError as e:
    logger.error(f"Failed to import FreeFire_pb2: {e}")
    raise ImportError("Ensure FreeFire_pb2.py is in the proto/ directory and correctly generated.") from e

# === Settings ===
try:
    MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
    MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
    logger.info("Successfully decoded MAIN_KEY and MAIN_IV")
except Exception as e:
    logger.error(f"Failed to decode MAIN_KEY or MAIN_IV: {e}")
    raise

USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
RELEASEVERSION = "OB53"

app = Flask(__name__)

# === Helper Functions ===
def pad(text: bytes) -> bytes:
    try:
        padding_length = AES.block_size - (len(text) % AES.block_size)
        return text + bytes([padding_length] * padding_length)
    except Exception as e:
        logger.error(f"Padding failed: {e}")
        raise

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    try:
        # use named iv parameter for clarity
        aes = AES.new(key, AES.MODE_CBC, iv=iv)
        return aes.encrypt(pad(plaintext))
    except Exception as e:
        logger.error(f"AES encryption failed: {e}")
        raise

async def json_to_proto(json_data: str, proto_message) -> bytes:
    """
    json_data: JSON string or dict-like string
    proto_message: an instance of the protobuf message (e.g. FreeFire_pb2.LoginReq())
    """
    try:
        parsed = json.loads(json_data) if isinstance(json_data, str) else json_data
        json_format.ParseDict(parsed, proto_message)
        return proto_message.SerializeToString()
    except json.JSONDecodeError as e:
        logger.error(f"JSON parsing failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Protobuf conversion failed: {e}")
        raise

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    # account is expected to be "uid=...&password=..."
    payload = f"{account}&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    try:
        async with httpx.AsyncClient() as client:
            logger.info(f"Sending access token request to {url}")
            resp = await client.post(url, data=payload, headers=headers, timeout=20.0)
            resp.raise_for_status()
            data = resp.json()
            access_token = data.get("access_token", "0")
            open_id = data.get("open_id", "0")
            if access_token == "0" or open_id == "0":
                logger.warning(f"Invalid access token or open_id received: {data}")
            return access_token, open_id
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error during access token request: {e.response.status_code} - {e.response.text}")
        raise
    except Exception as e:
        logger.error(f"Failed to get access token: {e}")
        raise

async def create_jwt(uid: str, password: str):
    try:
        account = f"uid={uid}&password={password}"
        logger.info(f"Generating JWT for uid: {uid}")
        token_val, open_id = await get_access_token(account)
        body = json.dumps({
            "open_id": open_id,
            "open_id_type": "4",
            "login_token": token_val,
            "orign_platform_type": "4"
        })
        proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
        url = "https://loginbp.ggblueshark.com/MajorLogin"
        headers = {
            'User-Agent': USERAGENT,
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Expect': "100-continue",
            'X-Unity-Version': "2022.3.47f1",
            'X-GA': "v1 1",
            'ReleaseVersion': RELEASEVERSION
        }
        async with httpx.AsyncClient() as client:
            logger.info(f"Sending JWT request to {url}")
            resp = await client.post(url, data=payload, headers=headers, timeout=30.0)
            resp.raise_for_status()
            # Response is expected to be protobuf bytes for LoginRes
            try:
                login_res_msg = FreeFire_pb2.LoginRes.FromString(resp.content)
                msg = json.loads(json_format.MessageToJson(login_res_msg))
            except Exception as parse_e:
                logger.error(f"Failed to parse LoginRes protobuf: {parse_e}")
                # include raw response text snippet for debugging
                raise
            token = msg.get('token', '0')
            if token == '0':
                logger.warning(f"No token received in response: {msg}")
            return {
                'token': f"{token}",
                'region': msg.get('lockRegion', '0'),
                'server_url': msg.get('serverUrl', '0')
            }
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error during JWT creation: {e.response.status_code} - {e.response.text}")
        raise
    except Exception as e:
        logger.error(f"JWT creation failed: {e}")
        raise

# === Health Check Route (for debugging) ===
@app.route('/api/health', methods=['GET'])
def health_check():
    logger.info("Health check endpoint called")
    return jsonify({"status": "API is running", "version": RELEASEVERSION}), 200

# === API Route: generate token ===
@app.route('/api/token', methods=['GET'])
def get_jwt():
    try:
        logger.info(f"Received request to /api/token with args: {request.args}")
        uid = request.args.get('uid')
        password = request.args.get('password')
        if not uid or not password:
            logger.warning("Missing uid or password in request")
            return jsonify({"error": "Please provide both uid and password."}), 400
        result = asyncio.run(create_jwt(uid, password))
        logger.info(f"JWT generated successfully for uid: {uid}")
        return jsonify(result), 200
    except Exception as e:
        logger.error(f"Error in get_jwt: {e}")
        return jsonify({"error": f"Failed to generate JWT: {str(e)}"}), 500

# === API Route: decode JWT (no verification, just decoding) ===
@app.route('/api/decode', methods=['GET'])
def decode_jwt():
    """
    Example:
      /api/decode?jwt=<jwt_token>
    Returns JSON with decoded header, payload and signature (if present).
    """
    try:
        jwt_token = request.args.get('jwt') or request.args.get('token')
        if not jwt_token:
            return jsonify({"error": "Please provide a JWT token via 'jwt' or 'token' query parameter."}), 400

        parts = jwt_token.split('.')
        if len(parts) < 2:
            return jsonify({"error": "Malformed JWT: expected at least header and payload separated by '.'"}), 400

        def b64url_decode(s: str) -> bytes:
            # Fix padding then base64-decode
            s = s.replace('-', '+').replace('_', '/')
            padding = len(s) % 4
            if padding != 0:
                s += '=' * (4 - padding)
            return base64.b64decode(s)

        header_json = {}
        payload_json = {}
        signature = parts[2] if len(parts) > 2 else ""

        try:
            raw_header = b64url_decode(parts[0])
            header_json = json.loads(raw_header.decode('utf-8'))
        except Exception as e:
            logger.warning(f"Failed to decode JWT header: {e}")
            header_json = {"error": "Failed to decode header", "raw": parts[0]}

        try:
            raw_payload = b64url_decode(parts[1])
            payload_json = json.loads(raw_payload.decode('utf-8'))
        except Exception as e:
            logger.warning(f"Failed to decode JWT payload: {e}")
            payload_json = {"error": "Failed to decode payload", "raw": parts[1]}

        return jsonify({
            "header": header_json,
            "payload": payload_json,
            "signature": signature
        }), 200

    except Exception as e:
        logger.error(f"Error decoding JWT: {e}")
        return jsonify({"error": f"Failed to decode JWT: {str(e)}"}), 500

# === Startup() to avoid __main__ crash if called ===
async def startup():
    logger.info("Running startup initialisation (no-op)")
    # If you need any async init (metrics, warmups), do it here.
    return

# === Startup / run ===
import sys

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    print(f"[🚀] Starting {__name__.upper()} on port {port} ...")
    try:
        asyncio.run(startup())
    except Exception as e:
        print(f"[⚠️] Startup warning: {e} — continuing without full initialization")
    app.run(host='0.0.0.0', port=port, debug=False)