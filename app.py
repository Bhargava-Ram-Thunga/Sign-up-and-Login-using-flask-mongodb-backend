from flask import Flask, jsonify, request, render_template, redirect #type: ignore
from flask_cors import CORS #type: ignore
from bcrypt import checkpw,hashpw,gensalt #type: ignore
from pymongo import MongoClient #type: ignore
from bson.objectid import ObjectId #type: ignore
import jwt,datetime #type: ignore
from functools import wraps 

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] = "IAMPRO"


# pass = uQj75crnLZC4P9BQ
cs = "mongodb+srv://br5183268:uQj75crnLZC4P9BQ@users.j8qynzk.mongodb.net/"
client = MongoClient(cs)
db = client["users"]
table = db["users_collection"] 

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if (auth_header.startswith("Bearer ")):
                token = auth_header.split(" ")[1]
        if not token :
            return {"message" : "Token is missing"},401
        try:
            data = jwt.decode(token,app.config['SECRET_KEY'],algorithms = ["HS256"])
            current_user = data['username']
        except jwt.ExpiredSignatureError:
            return {"message" : "Token has expired"},401
        except jwt.InvalidTokenError:
            return {"message" : "Token is Invalid"},401
        return f(current_user,*args,**kwargs)
    return decorated



def getData(data):
    return {
        "firstname" : data.get("firstName"),
        "lastname" : data.get("lastName"),
        "email" : data.get("email"),
        "password" : hashpw(data.get("password").encode("utf-8"),gensalt()).decode("utf-8"),
    }


@app.route('/signup',methods=["POST"])
def signup():
    data = request.json
    # print(data)
    # print(getData(data))
    table.insert_one(getData(data))
    return "hello this is signup"

@app.route('/login',methods=["POST"])
def login():
    auth_data = request.json
    email = auth_data.get("email")
    password = auth_data.get("password")

    user = table.find_one({"email" : email})
    if not user :
        return jsonify( {"message" : "user not found"}),404
    
    ispass = checkpw(password.encode('utf-8'),user["password"].encode('utf-8'))
    if not ispass:
        return jsonify( {"message" : "password is wrong"}),401
    token = jwt.encode({
        'email' : email,
        'exp' : datetime.datetime.utcnow()+datetime.timedelta(minutes= 60)
    },app.config['SECRET_KEY'],algorithm = "HS256")
    print(token)
    return jsonify({"token":token}),200




if __name__ == "__main__":
    app.run(debug = True)