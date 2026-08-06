# What is vAPI

![https://github.com/jorritfolmer/vulnerable-api/workflows/vAPI/badge.svg](https://github.com/jorritfolmer/vulnerable-api/workflows/vAPI/badge.svg)

vAPI is an API written specifically to illustrate common API vulnerabilities.
It is implemented using Python Flask + Connexion and consists of a user database and a token database.

## How is this version different from all the other vulnerable-API forks on GitHub?

1. Python 3.6, 3.7, 3.8, 3.9 and 3.10 supported and tested.
1. OpenAPI first, using [Connexion](https://github.com/zalando/connexion)
1. Includes tests and an [OpenAPI 3 fuzzer](https://github.com/vwt-digital/openapi3-fuzzer)
1. It adds a business relevant widget reservation endpoint.
1. It adds basic application logging (vAPI.log) for purple teaming demo purposes! 
1. Log format is Splunk CIM compliant key=value right out of the box.

## Usage

1. `git clone https://github.com/jorritfolmer/vulnerable-api.git`
1. `virtualenv venv`
1. `source venv/bin/activate`
1. `pip install -r requirements`
1. `python ./vAPI.py -p <port>`
1. have fun with OWASP ZAP, Burp or Postman

## vAPI Process flow

1. Request token from /tokens
    - Returns an auth token
    - Returns expiration date of auth token
    - Returns a user id
1. Request widget reservation from /widget
    - Requires the auth token
1. Request user record from /user/\<user\_id\>
    - Requires the auth token
    - Returns the user record for the user specfied, provided the auth token is not expired and is valid for the user id specified
    - Each user can only access their own record

## OpenAPI 3 spec

Also contained in this repo is the API specification file to load in e.g. Burp or OWASP ZAP for fun and profit.

- OpenAPI Spec 3 (OAS3) file: `openapi/vAPI.yaml`

## Known vulnerabilities

1. Insecure transport
2. User enumeration
3. Information disclosure
4. Authentication bypass
5. No input validation
6. SQL injection
8. Weak session token crypto
9. Poor session validation
10. Plaintext storage of secrets
11. Command injection
12. Regex denial of service
13. Cross Site Scripting
14. XML XXE and billion laughs
15. Missing security headers 

### Vulnerabilities per endpoint

| method | endpoint       | input               | vuln            
|--------|----------------|---------------------|-----------------
| GET    | /              | -                   | 15              
| GET    | /tokens        | -                   | 10              
| POST   | /tokens        | post                | 14              
| POST   | /tokens        | post:username       | 2, 6, 8, 13, 14 
| POST   | /tokens        | post:password       | 2, 6, 8, 13, 14 
| GET    | /user/{userid} | header:x-auth-token | 4, 6, 8, 9      
| GET    | /user/{userid} | get: userid         | 2, 6, 10, 12    
| POST   | /user          | header:x-auth-token | 4, 6, 8, 9      
| POST   | /user          | post:username       | 6, 9, 12, 13    
| POST   | /user          | post:username       | 6, 9, 13        
| GET    | /uptime{flag}  | -                   | 11, 13
| POST   | /widget        | header:x-auth-token | 4, 6, 8, 9      
| POST   | /widget        | post:widget         | 12              


## Examples

### /tokens endpoint

````
$ curl -X POST -H "Content-type: application/json" http://localhost:8081/tokens \
-d '
{
  "auth": {
    "passwordCredentials": {
      "username":"user1",
      "password":"pass1"
      }
  }
}'
````

### /widget endpoint

```
POST /widget HTTP/1.1
Content-Type: application/json
X-Auth-Token: USER TOKEN

{"widget":
    {"name": "widget01"}
}
```


### /user endpoint

```
POST /user HTTP/1.1
Content-type: application/json
X-Auth-Token: ADMIN TOKEN

{"user":
	{"username": "user",
	"password": "pass"}
}
```

## Docker

1. `docker build -t vapi .`
1. `docker run -p 8081:8081 vapi`

## Testing

From the project root:

```
pip install -r requirements-test.txt
coverage run -m unittest
coverage report -m

```
