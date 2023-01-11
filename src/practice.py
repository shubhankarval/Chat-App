
# import hashlib
# import codecs

# s = "/image/cat.jpg"
# images = ["cat.jpg","dog","eagle"]
# m = "name=Mitch"
# l = [b'm',b'lol',b'p']
# x = "".join(list(map(lambda x: x.decode("utf-8"),l)))
# #print(x)
# #print(type(x))
# #print(b"".join(l))

# j = ["r","pol","u"]
# matching = [s for s in j if "p" in s][0]
import re
import bcrypt
import hashlib

#print(bool(re.match('^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])', 'SOME1')))
if not bool(re.match('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*(_|[^\w])).+$', 'SOME@pp')): print("lol")
x="password"
g=hashlib.sha256(x.encode()).hexdigest()
# print(g)

res = {}
if bool(res): print("lol")












'''
elif path == "/register":
                    splitArr = data.decode().split("\r\n\r\n")
                    username = splitArr[2].split("\r\n")[0]
                    password = splitArr[3].split("\r\n")[0]
                    
                    if bool(re.match('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*(_|[^\w])).+$', password)) and len(password) >= 8:
                        salt = bcrypt.gensalt() #in bytes
                        hashed = bcrypt.hashpw(password.encode(), salt) #in bytes

                        usernames.insert_one({"username":username,"password":hashed,"salt":salt}) #salt and hashed in bytes

                        resp = buildOkResponse("text/plain",True,"You've successfully registered!")
                        self.request.sendall(resp)
                    
                    else:
                        resp = buildOkResponse("text/plain",True,"Password doesn't meet all criteria")
                        self.request.sendall(resp)
                
                elif path == "/login":
                    splitArr = data.decode().split("\r\n\r\n")
                    username = splitArr[2].split("\r\n")[0]
                    password = splitArr[3].split("\r\n")[0]

                    result = usernames.find_one({"username":username})

                    if result == None:
                        resp = buildOkResponse("text/plain",True,"Login failed")
                        self.request.sendall(resp)  
                    elif result.has_key("auth"):
                        resp = build303Response("")
                        self.request.sendall(resp) 
                    else:
                        hashed = bcrypt.hashpw(password.encode(), result["salt"])
                        if hashed != result["password"]:
                            resp = buildOkResponse("text/plain",True,"Login failed")
                            self.request.sendall(resp)  
                        else:
                            token = generateToken()
                            hashed_token = hashlib.sha256(token.encode()).hexdigest()
                            usernames.update_one({"username":username},{"$set": {"auth":hashed_token} })
                            resp = buildLoginResponse(token)
                            self.request.sendall(resp)
'''