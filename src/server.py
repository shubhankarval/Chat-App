import socketserver
import sys
import string, random
import hashlib, codecs
import json
from pymongo import MongoClient
import bcrypt
import re

myclient = MongoClient('mongo')
mydb = myclient["cse312"]
chats = mydb["chats"]
users = mydb["users"]
IDs = mydb["IDs"]
if IDs.count_documents({}) == 0:
    IDs.insert_one({"i":0})
    #print(IDs.find_one())
# IDs.delete_many({})
# users.delete_many({})


sockets=[]

usernames = mydb["usernames"]
# usernames.delete_many({})

def buildResponse(code):
    if code == 404:
        return  "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: 36\r\n\r\nThe requested content does not exist".encode()
    elif code == 403:
        return "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 34\r\n\r\nYour submission was not authorized".encode()
    elif code == 204:
        return "HTTP/1.1 204 No Content\r\n\r\n".encode()

def build303Response(path):
    return "HTTP/1.1 301 Moved Permanently\r\nLocation: /{}\r\n\r\n".format(path).encode()

def build101Response(key):
    return "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {}\r\n\r\n".format(key).encode()

def buildOkResponse(contentType, charset, content):
    response = "HTTP/1.1 200 OK\r\n"
    response += "Content-Type: {}".format(contentType)
    if charset:
        response += "; charset=utf-8"
    response += "\r\n"
    response += "Content-Length: {}\r\n".format(len(content))
    response += "X-Content-Type-Options: nosniff\r\n\r\n"
    if  type(content) == str:
        response += content
        return response.encode()
    response = response.encode()
    response += content
    return response

def buildHTMLResponse(content, visits):
    response = "HTTP/1.1 200 OK\r\n"
    response += "Content-Type: text/html; charset=utf-8\r\n"
    response += "Content-Length: {}\r\n".format(len(content))
    response += "X-Content-Type-Options: nosniff\r\n"
    if visits == 0:
        response += "Set-Cookie: visits=1; Max-Age=4000; HttpOnly\r\n\r\n"
    else:
        response += "Set-Cookie: visits={}; Max-Age=4000; HttpOnly\r\n\r\n".format(str(visits+1))
    response = response.encode()
    response += content
    return response

def buildLoginResponse(token):
    response = "HTTP/1.1 200 OK\r\n"
    response += "Content-Type: text/plain\r\n"
    content = "You're logged in"
    response += "Content-Length: {} \r\n".format(str(len(content)))
    response += "Set-Cookie: auth={}; Max-Age=4000; HttpOnly\r\n".format(token)
    response += "X-Content-Type-Options: nosniff\r\n\r\n"
    response += content
    return response.encode()

def unmaskPayload(mask_key,payload):
    content=""
    i = 0
    for j in payload:
        if i == len(mask_key):
            i = 0
        content += str(int(j,2) ^ int(mask_key[i],2))
        i+=1

    content = int(content, 2).to_bytes((len(content) + 7) // 8, byteorder='big')
    content = cleanString(content)
    return content

def read_file(file):
    with open (file, "rb") as f:
        data = f.read()
        return data

def write_file(file, data):
    with open (file, "wb") as f:
        f.write(data)

def fileToString(file):
    with open (file, "r") as f:
        data = f.read()
        return data

def generateToken():
    char = string.ascii_letters
    return ''.join(random.choice(char) for i in range(23))

def cleanString(s):
    return s.strip().replace(b"&",b"&amp").replace(b"<",b"&lt").replace(b">",b"&gt")

class MyTCPHandler(socketserver.BaseRequestHandler):
    clients = []
    names_lst=[]
    captions=[]
    tokens=[]

    def handle(self):
        data = self.request.recv(2000)
        if data!=b"":

            #updating client info
            client_id = self.client_address[0] + ":" + str(self.client_address[1])
            # print(client_id + " is sending data:")
            # print(data)
            self.clients.append(client_id) 
            # print("\n")
            sys.stdout.flush()
            sys.stderr.flush()

            #get headers of request
            headers = data.decode().split("\r\n")
            arr = headers[0].split(" ") #get first line of headers
            path = arr[1]

            images = ["cat.jpg","dog.jpg","eagle.jpg","elephant.jpg","flamingo.jpg","kitten.jpg","parrot.jpg","rabbit.jpg"]

            #checking for GET requests
            if arr[0] == "GET" and arr[2] == "HTTP/1.1":

                #obj 1 - /hello
                if path == "/hello":
                    resp = buildOkResponse("text/plain",True,"Hello User!")
                    self.request.sendall(resp)              

                #obj 2 - /hi
                elif path == "/hi":
                    resp = build303Response("hello")
                    self.request.sendall(resp)

                #obj 3 - HTML File
                elif path == "/":
                    file = fileToString("index.html")
                    
                    if self.names_lst:
                        names = ""
                        i = 0 
                        while(i < len(self.names_lst)):
                            names+="<p>Name: {}, Comment: {}</p>\n".format(self.names_lst[i],self.names_lst[i+1])
                            i+=2
                        index = file.find("{{names}}")
                        file = file[:index] + names + file[index:]
                    
                    if self.captions:
                        imgs = "" 
                        i = 0 
                        while(i < len(self.captions)):
                            imgs+="<p>{}</p>\n".format(self.captions[i+1])
                            imgs+="<br>"
                            imgs+='<img src="client/{}"/>'.format(self.captions[i]) 
                            i+=2
                        index = file.find("{{img}}")
                        file = file[:index] + imgs + file[index:]

                    file = file.replace("{{names}}","")
                    file = file.replace("{{img}}","")

                    #generate XSRF token
                    token = generateToken()
                    self.tokens.append(token)
                    file = file.replace("{{token}}",token)

                    #cookies
                    cookies=""
                    visits = 0
                    res={}
                    for header in reversed(headers):
                        if "Cookie:" in header:
                            cookies=header
                            break
                    if cookies!="":
                        cookieArray = cookies.split("Cookie:")[1].split(';')
                        for c in cookieArray:
                            if "visits=" in c:
                                visits= int(c.strip().split("=")[1])
                            if "auth=" in c:
                                auth = c.split("=")[1].strip()
                                authHash = hashlib.sha256(auth.encode()).hexdigest()
                                res = usernames.find_one({"auth":authHash}) 
                                
                                    
                    if res==None or len(res)==0:
                        file = file.replace("{{welcome}}","")
                    else:
                        file = file.replace("{{welcome}}","<h2>Welcome back {}!</h2>".format(res["username"]))

                    
                    file = file.replace("{{visits}}",str(visits+1))

                    html_file = file.encode("utf-8")
                    resp = buildHTMLResponse(html_file,visits)
                    self.request.sendall(resp)
            
                #obj 3 - JS File
                elif path == "/functions.js":
                    js_file = read_file("functions.js")
                    resp = buildOkResponse("text/javascript",True,js_file)
                    self.request.sendall(resp)

                #obj 3 - CSS File
                elif path == "/style.css":
                    css_file = read_file("style.css")
                    resp = buildOkResponse("text/css",True,css_file)
                    self.request.sendall(resp)
            
                #obj 4 - UTF File
                elif path == "/utf.txt":
                    utf_file = read_file("utf.txt")
                    resp = buildOkResponse("text/plain",True,utf_file)
                    self.request.sendall(resp)
                
                #obj 5 - Images
                elif path[0:7] == "/image/" and path[7:] in images:
                    img = "image/" + path[7:]
                    img_file = read_file(img)
                    resp = buildOkResponse("image/jpeg",False,img_file)
                    self.request.sendall(resp)

                #Client uploaded images
                elif path[0:8] == "/client/" and path[8:] in self.captions:
                    img = path[8:]
                    img_file = read_file(img)
                    resp = buildOkResponse("image/jpeg",False,img_file)
                    self.request.sendall(resp)
                
                #obj 1 (HW 2) - query
                elif path[0:8] == "/images?" and "name" in path[8:] and "images" in path[8:]:
                        lst = path[8:].split("&")
                        key_1 = lst[0].split("=")
                        key_2 = lst[1].split("=")
                        if(key_1[0] == "name"):
                            name = key_1[1]
                            img_list = key_2[1].split("+")
                        else:
                            name = key_2[1]
                            img_list = key_1[1].split("+")

                        file = fileToString("custom.html")
                        file = file.replace("{{name}}",name)

                        imgs = ""
                        for i in img_list:
                            imgs += '<img src="image/{}.jpg"/>\n'.format(i)
                        index = file.find("{{loop}}")
                        file = file[:index] + imgs + file[index:]

                        file = file.replace("{{loop}}","")

                        html_file = file.encode()
                        resp = buildOkResponse("text/html",True,html_file)
                        self.request.sendall(resp)
                
                #websockets
                elif path == "/websocket":
                    key = ""
                    for header in headers:
                        if "Sec-WebSocket-Key" in header:
                            key = header[header.find(':')+1:].strip()
                    key = key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
                    sha1 = hashlib.sha1(key.encode()).hexdigest()
                    hexKey = codecs.encode(codecs.decode(sha1, 'hex'), 'base64').decode()[0:-1]
                    resp = build101Response(hexKey)
                    self.request.sendall(resp)

                    sockets.append(self)
                    
                    if chats.count_documents({}) != 0:
                        for socket in sockets:
                            lst = list(chats.find())
                            for ele in lst:
                                socket.request.sendall(ele["message"])


                    while True:
                        recieved_data = self.request.recv(2000)
                        
                        if recieved_data!=b'':
                            # print(recieved_data)
                            bits = bin(int.from_bytes(recieved_data, "big"))[2:]
                            if bits[4:8] != "1000":
                                length = int(bits[9:16],2)

                                content = ""
                                startBits = ""
                                content_length=""

                                if length<126:
                                    mask_key = bits[16:48]
                                    payload = bits[48:]

                                    content = unmaskPayload(mask_key,payload)

                                    #print(content)

                                    #sending response
                                    #print(len(content))
                                    content_length = bin(len(content))[2:]
                                    content_length = '0'*(7-len(content_length)) + content_length
                                    startBits = '100000010'

                                        
                                elif length==126:
                                    mask_key = bits[32:32+32]
                                    payload = bits[64:]
                                    content = unmaskPayload(mask_key,payload)

                                    # print(content)

                                    #sending response
                                    content_length = bin(len(content))[2:]
                                    content_length = '0'*(16-len(content_length)) + content_length
                                    startBits = '100000010' + '1111110'
                                
                                toSend = startBits + content_length
                                resp = int(toSend, 2).to_bytes((len(toSend) + 7) // 8, byteorder='big') + content

                                chats.insert_one({"message": resp})

                                for socket in sockets:
                                    socket.request.sendall(resp)
                            
                            else:
                                sockets.remove(self)
                                break
                
                #/users
                elif path == "/users":
                    content = json.dumps(list(users.find()))
                    resp = buildOkResponse("application/json",False,content)
                    self.request.sendall(resp)
                
                #/users/{id}
                elif path[0:7] == "/users/":
                    uniqueID = int(path[7:].strip())
                    userList = list(users.find({"_id":uniqueID}))
                    if userList:
                        user = json.dumps(userList[0])
                        resp = buildOkResponse("application/json",False,user)
                        self.request.sendall(resp)
                    else:
                        resp = buildResponse(404)
                        self.request.sendall(resp)
                
                # /auth
                elif path == "/auth":
                    cookies=""
                    res={}
                    for header in reversed(headers):
                        if "Cookie:" in header:
                            cookies=header
                            break
                    if cookies!="":
                        cookieArray = cookies.split("Cookie:")[1].split(';')
                        for c in cookieArray:
                            if "auth=" in c:
                                auth = c.split("=")[1].strip()
                                authHash = hashlib.sha256(auth.encode()).hexdigest()
                                res = usernames.find_one({"auth":authHash}) 
                        if res==None or len(res)==0:
                            resp= "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 40 \r\n\r\nError: You must log in to view this page".encode()
                            self.request.sendall(resp)
                        else:
                            print("lol")
                            resp=buildOkResponse("text/plain",True,"{}, you have been authenticated!".format(res["username"]))
                            self.request.sendall(resp)
                    else:
                        resp= "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 40 \r\n\r\nError: You must log in to view this page".encode()
                        self.request.sendall(resp)


                #obj 2 - 404
                else:
                    resp = buildResponse(404)
                    self.request.sendall(resp)
            
            #POST requests
            if arr[0] == "POST" and arr[2] == "HTTP/1.1":
                
                if path == "/users":
                    userInfo= json.loads(data.split(b"\r\n\r\n")[1].decode())

                    previousID = IDs.find_one()["i"]
                    newID = previousID + 1
                    userInfo["_id"] = newID
                    
                    users.insert_one(userInfo)
                    IDs.update_one({"i":previousID},{ "$set": { "i": newID }})

                    userInfoJson = json.dumps(userInfo)

                    resp = ("HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n".format(len(userInfoJson)) + userInfoJson).encode()
                    self.request.sendall(resp)
                
                elif path == "/register":
                    splitArr = data.decode().split("\r\n\r\n")
                    username = splitArr[2].split("\r\n")[0]
                    password = splitArr[3].split("\r\n")[0]
                    
                    
                    if bool(re.match('^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*(_|[^\w])).+$', password)) and len(password) >= 8:
                        salt = bcrypt.gensalt() #in bytes
                        hashed = bcrypt.hashpw(password.encode(), salt) #in bytes

                        usernames.insert_one({"username":username,"password":hashed}) #hashed in bytes

                        resp = buildOkResponse("text/plain",True,"You've successfully registered!")
                        self.request.sendall(resp)
                    
                    else:
                        resp = buildOkResponse("text/plain",True,"Password doesn't meet all criteria")
                        self.request.sendall(resp)
                
                elif path == "/login":
                    splitArr = data.decode().split("\r\n\r\n")
                    username = splitArr[2].split("\r\n")[0]
                    password = splitArr[3].split("\r\n")[0]
                    print(f"pass={password}")

                    result = usernames.find_one({"username":username})

                    if result == None or bcrypt.checkpw(password.encode(),result["password"])==False:
                        resp = buildOkResponse("text/plain",True,"Login failed")
                        self.request.sendall(resp)
                    elif "auth" in result:
                        resp = build303Response("")
                        self.request.sendall(resp) 
                    else:
                        token = generateToken()
                        hashed_token = hashlib.sha256(token.encode()).hexdigest()
                        usernames.update_one({"username":username},{"$set": {"auth":hashed_token} })
                        resp = buildLoginResponse(token)
                        self.request.sendall(resp)
                    
                else:
                    for header in headers:
                        if "Content-Length" in header:
                            content_length = int(header[header.find(":")+1:].strip())
                
                    content=b""

                    while len(content) < content_length:
                        data += self.request.recv(1024)
                        if(data.find(b"\r\n\r\n") != -1):
                            lst = data.split(b"\r\n\r\n")
                            lst.pop(0)
                            content = b"\r\n\r\n".join(lst)

                    boundary = content.split(b"\r\n")[0]
                    contentList = content.split(boundary)

                    xsrf_token = contentList[3].split(b"\r\n\r\n")[1][0:23].decode()

                    if xsrf_token in self.tokens:

                        if path == "/comment":
                            name = contentList[1].split(b"\r\n\r\n")[1][0:-2]
                            name = cleanString(name).decode()
                            comment = contentList[2].split(b"\r\n\r\n")[1][0:-2]
                            comment = cleanString(comment).decode()
                            self.names_lst.append(name)
                            self.names_lst.append(comment)
                            resp = build303Response("")
                            self.request.sendall(resp)

                        elif path == "/image-upload":
                            imagelist = contentList[1].split(b"\r\n")
                            contentType = imagelist[2]
                            if b"image/jpeg" in contentType:
                                filename = cleanString(imagelist[1][imagelist[1].rfind(b'=') + 2: -1]).decode()
                                #save image
                                tempList = contentList[1].split(b"\r\n\r\n")
                                tempList.pop(0)
                                img = b"\r\n\r\n".join(tempList)
                                img = img[0:-2]
                                write_file(filename,img)
                                caption = contentList[2].split(b"\r\n\r\n")[1][0:-2]
                                caption = cleanString(caption).decode()
                                self.captions.append(filename)
                                self.captions.append(caption)
                                resp = build303Response("")
                                self.request.sendall(resp)
                            else:
                                resp = buildResponse(403)
                                self.request.sendall(resp)

                    else:
                        resp = buildResponse(403)
                        self.request.sendall(resp)
            
            if arr[0] == "PUT" and arr[2] == "HTTP/1.1":
                if path[0:7] == "/users/":
                    uniqueID = int(path[7:].strip())
                    userList = list(users.find({"_id":uniqueID}))
                    if userList:
                        userInfo = userList[0]
                        # userInfo.pop("_id")
                        updatedInfo = json.loads(data.split(b"\r\n\r\n")[1].decode())
                        users.update_one(userInfo,{ "$set": updatedInfo})

                        updatedInfo["_id"] = uniqueID
                        newUser = json.dumps(updatedInfo)
                        resp = buildOkResponse("application/json",False,newUser)
                        self.request.sendall(resp)
                    else:
                        resp = buildResponse(404)
                        self.request.sendall(resp)
            
            if arr[0] == "DELETE" and arr[2] == "HTTP/1.1":
                if path[0:7] == "/users/":
                    uniqueID = int(path[7:].strip())
                    userList = list(users.find({"_id":uniqueID}))
                    if userList:
                        userInfo = userList[0]
                        users.delete_one(userInfo)
                        resp = buildResponse(204)
                        self.request.sendall(resp)
                    else:
                        resp = buildResponse(404)
                        self.request.sendall(resp)
                
                elif path == "/chats":
                    chats.delete_many({})
                    resp = build303Response("")
                    self.request.sendall(resp)

 
if __name__ == "__main__":
    HOST = "0.0.0.0"
    PORT = 8000
    with socketserver.ThreadingTCPServer((HOST, PORT), MyTCPHandler) as server:
        server.serve_forever()