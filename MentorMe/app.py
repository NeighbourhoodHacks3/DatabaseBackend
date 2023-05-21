from flask import Flask, request, jsonify, render_template
from markupsafe import escape
from flask_pymongo import pymongo
from bson import ObjectId
import datetime
import bcrypt

from flask_cors import CORS, cross_origin

import db 

#### MongoDB Atlas backend ####

app = Flask(__name__)
CORS(app)

## User database ##
## Create user
# username, email and password are required, hidden in header
@app.route("/user/create")
@cross_origin()
def create_user():
    # Get username, email and password from body of request
    content_type = request.headers['Content-Type']
    if content_type == 'application/json':
        json = request.json
        username = json['username']
        email = json['email']
        password = json['password']
    else:
        return "Content-Type must be application/json!"

    # First check if user already exists
    # Query database for user with username or email
    user = db.users_collection.find_one({'$or': [{'username': username}, {'email': email}]})

    print(user)

    if user:
        return "User already exists!"

    # If not, create user                                   
    # Hash password
    hashed_password = hash_password(password)
    hashed_password_str = hashed_password.decode('utf-8')
    
    # Create user object
    newUser = {
        'username': username,
        'email': email,
        'hashedPassword': hashed_password_str
    }

    print(newUser)

    # If user does not exist, create user
    try:
        db.users_collection.insert_one(newUser)
    except:
        return "Error creating user!"

    # Return success message
    return "User created!"

## Read user
@app.route("/user/profile")
@cross_origin()
def get_user_profile():
    # Get userID from parameters
    user_id_param = request.args.get('userID')
    userID = ObjectId(user_id_param)

    # Query database for user with userID
    user = db.users_collection.find_one({'_id': userID})

    if user:
        user_profile = userProfileInfo(user)
        return jsonify(user_profile)
    else:
        return "User not found!"
    
## Update user
# username, email and password are required, hidden in header
@app.route("/user/update")
@cross_origin()
def update_user():
    # Get username, email and password from body of request
    content_type = request.headers['Content-Type']
    if content_type == 'application/json':
        json = request.json
        username = json['username']
        email = json['email']
        password = json['password']
    else:
        return "Content-Type must be application/json!"

    # First check if user exists
    # Query database for user with username or email
    user = db.users_collection.find_one({'$or': [{'username': username}, {'email': email}]})

    if user:
        # Check if password is correct
        if compare_password(password, user['hashedPassword']):
            # Update other description, jobTitle, and the experience array
            if 'description' in json:
                description = json['description']
            if 'jobTitle' in json:
                jobTitle = json['jobTitle']
            if 'experience' in json:
                experience = json['experience']

            # Update user object
            updatedUser = {
                'username': user['username'],
                'email': user['email'],
                'hashedPassword': user['hashedPassword'],
                'description': description,
                'jobTitle': jobTitle,
                'experience': experience
            }

            # Update user
            try:
                db.users_collection.update_one({'_id': user['_id']}, {'$set': updatedUser})
            except:
                return "Error updating user!"
            
            # Return success message
            return "User updated!"
        else:
            return "Incorrect password!"
    else:
        return "User not found!"
    
## Request post database ##
## Create request post
# userID, title, description, and tags are required, hidden in header
@app.route("/requestPost/create")
@cross_origin()
def create_request_post():
    # Get userID, title, description, and tags from body of the request
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        json = request.json
        userID = json['userID']
        title = json['title']
        description = json['description']
        tags = json['tags']
        location = json['location']
        payment = json['payment']
    else:
        return "Error: Content-Type must be application/json!"

    # Create request post object
    newRequestPost = {
        'userID': userID,
        'title': title,
        'description': description,
        'tags': tags,
        'postTime': get_current_time(),
        'location': location,
        'payment': payment,
        'requestOpen': True
    }

    # Create request post
    try:
        db.requestPosts_collection.insert_one(newRequestPost)
    except:
        return "Error creating request post!"

    # Return success message
    return "Request post created!"

## Read request post
@app.route("/requestPost")
@cross_origin()
def get_request_post():
    requestPost_id_param = request.args.get('requestPostID')
    requestPostID = ObjectId(requestPost_id_param)

    # Query database for request post with requestPostID
    requestPost = db.requestPosts_collection.find_one({'_id': requestPostID})

    if requestPost:
        # convert ObjectId to string
        requestPost['_id'] = str(requestPost['_id'])
        return jsonify(requestPost)
    else:
        return "Request post not found!"

## Get paginated request posts
# page is required, hidden in header
@app.route("/requestPosts")
@cross_origin()
def get_request_posts():
    # Get page from parameters
    page = int(request.args.get('page')) - 1

    # Query database for request posts
    requestPosts = db.requestPosts_collection.find().sort('postTime', pymongo.DESCENDING).skip(page * 10).limit(10)

    # Convert request posts to list
    requestPostsList = list(requestPosts)

    # Convert ObjectId to string
    for requestPost in requestPostsList:
        requestPost['_id'] = str(requestPost['_id'])

    return jsonify(requestPostsList)

## Update request post (close request post)
# requestPostID is required, hidden in header
@app.route("/requestPost/update")
@cross_origin()
def update_request_post():
    # Get requestPostID from body of the request
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        json = request.json
        requestPost_id_param = json['requestPostID']
        requestOpen = json['requestOpen']
    else:
        return "Error: Content-Type must be application/json!"
    
    requestPostID = ObjectId(requestPost_id_param)

    # Query database for request post with requestPostID
    requestPost = db.requestPosts_collection.find_one({'_id': requestPostID})

    if requestPost:
        # check if request post is already closed
        if requestPost['requestOpen'] == False and requestOpen == False:
            return "Request post is already closed!"
        
        if requestPost['requestOpen'] == True and requestOpen == True:
            return "Request post is already open!"
        
        # Update request post
        try:
            db.requestPosts_collection.update_one({'_id': requestPost['_id']}, {'$set': {'requestOpen': requestOpen}})
        except:
            return "Error updating request post!"

        # Return success message
        return "Request post updated!"
    
    else:
        return "Request post not found!"
    
## Request Comment database ##
## Create request comment
# userID, requestPostID, and comment are required, hidden in header
@app.route("/requestComment/create")
@cross_origin()
def create_request_comment():
    # Get userID, requestPostID, and comment from body of the request
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        json = request.json
        userID = json['userID']
        requestPostID = json['requestPostID']
        comment = json['comment']
    else:
        return "Error: Content-Type must be application/json!"
    
    # Check if user exists
    user = db.users_collection.find_one({'_id': ObjectId(userID)})

    if not user:
        return "User not found!"

    # Check if request post exists
    requestPost = db.requestPosts_collection.find_one({'_id': ObjectId(requestPostID)})
    
    if not requestPost:
        return "Request post not found!"
    else:
        # Check if request post is closed
        if requestPost['requestOpen'] == False:
            return "Request post is closed!"
    
    # Create request comment object
    newRequestComment = {
        'userID': userID,
        'requestPostID': requestPostID,
        'comment': comment,
        'commentTime': get_current_time()
    }

    # Create request comment
    try:
        db.requestComments_collection.insert_one(newRequestComment)
    except:
        return "Error creating request comment!"

    # Return success message
    return "Request comment created!"

## Get request comments for a request post
# requestPostID is required, hidden in header
@app.route("/requestComments")
@cross_origin()
def get_request_comments():
    # Get requestPostID from parameters
    try:
        requestPostID = request.args.get('requestPostID')
    except:
        return "Error getting request post ID!"
    
    # Query database for request comments with requestPostID
    requestComments = db.requestComments_collection.find({'requestPostID': requestPostID}).sort('commentTime', pymongo.DESCENDING)

    # Convert request comments to list
    requestCommentsList = list(requestComments)

    # Convert ObjectId to string
    for requestComment in requestCommentsList:
        requestComment['_id'] = str(requestComment['_id'])

    return jsonify(requestCommentsList)

## Offer post database ##
## Create offer post
# userID, title, description, and tags are required, hidden in header
@app.route("/offerPost/create")
@cross_origin()
def create_offer_post():
    # Get userID, title, description, and tags from body of the request
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        json = request.json
        userID = json['userID']
        title = json['title']
        description = json['description']
        tags = json['tags']
        location = json['location']
        payment = json['payment']
    else:
        return "Error: Content-Type must be application/json!"

    # Create offer post object
    newOfferPost = {
        'userID': userID,
        'title': title,
        'description': description,
        'tags': tags,
        'postTime': get_current_time(),
        'location': location,
        'payment': payment,
        'offerOpen': True
    }

    # Create offer post
    try:
        db.offerPosts_collection.insert_one(newOfferPost)
    except:
        return "Error creating offer post!"

    # Return success message
    return "Offer post created!"

## Read offer post
@app.route("/offerPost")
@cross_origin()
def get_offer_post():
    try:
        offerPost_id_param = request.args.get('offerPostID')
    except:
        return "Error getting offer post ID!"
    
    offerPostID = ObjectId(offerPost_id_param)

    # Query database for offer post with offerPostID
    offerPost = db.offerPosts_collection.find_one({'_id': offerPostID})

    if offerPost:
        # convert ObjectId to string
        offerPost['_id'] = str(offerPost['_id'])
        return jsonify(offerPost)
    else:
        return "Offer post not found!"
    
## Get paginated offer posts
# page is required, hidden in header
@app.route("/offerPosts")
@cross_origin()
def get_offer_posts():
    # Get page from parameters
    page = int(request.args.get('page')) - 1

    # Query database for offer posts
    offerPosts = db.offerPosts_collection.find().sort('postTime', pymongo.DESCENDING).skip(page * 10).limit(10)

    # Convert offer posts to list
    offerPostsList = list(offerPosts)

    # Convert ObjectId to string
    for offerPost in offerPostsList:
        offerPost['_id'] = str(offerPost['_id'])

    return jsonify(offerPostsList)

## Update offer post (close offer post)
# offerPostID is required, hidden in header
@app.route("/offerPost/update")
@cross_origin()
def update_offer_post():
    # Get offerPostID from body of the request
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        json = request.json
        offerPost_id_param = json['offerPostID']
        offerOpen = json['offerOpen']
    else:
        return "Error: Content-Type must be application/json!"
    
    offerPostID = ObjectId(offerPost_id_param)

    # Query database for offer post with offerPostID
    offerPost = db.offerPosts_collection.find_one({'_id': offerPostID})

    if offerPost:
        # Check if offer post is already closed
        if offerPost['offerOpen'] == False and offerOpen == False:
            return "Offer post already closed!"
        
        if offerPost['offerOpen'] == True and offerOpen == True:
            return "Offer post already open!"
        
        # Update offer post
        try:
            db.offerPosts_collection.update_one({'_id': offerPost['_id']}, {'$set': {'offerOpen': offerOpen}})
        except:
            return "Error updating offer post!"

        # Return success message
        return "Offer post updated!"
    
    else:
        return "Offer post not found!"
    
## Offer Comment database ##
## Create offer comment
# userID, offerPostID, and comment are required, hidden in header
@app.route("/offerComment/create")
@cross_origin()
def create_offer_comment():
    # Get userID, offerPostID, and comment from body of the request
    content_type = request.headers.get('Content-Type')
    if (content_type == 'application/json'):
        json = request.json
        userID = json['userID']
        offerPostID = json['offerPostID']
        comment = json['comment']
    else:
        return "Error: Content-Type must be application/json!"
    
    # Check if user exists
    user = db.users_collection.find_one({'_id': ObjectId(userID)})

    if not user:
        return "User not found!"
    
    # Check if offer post exists
    offerPost = db.offerPosts_collection.find_one({'_id': ObjectId(offerPostID)})

    if not offerPost:
        return "Offer post not found!"
    else:
        # Check if request post is closed
        if offerPost['offerOpen'] == False:
            return "Offer post is closed!"

    # Create offer comment object
    newOfferComment = {
        'userID': userID,
        'offerPostID': offerPostID,
        'comment': comment,
        'commentTime': get_current_time()
    }

    # Create offer comment
    try:
        db.offerComments_collection.insert_one(newOfferComment)
    except:
        return "Error creating offer comment!"

    # Return success message
    return "Offer comment created!"

## Get offer comments for an offer post
# offerPostID is required, hidden in header
@app.route("/offerComments")
@cross_origin()
def get_offer_comments():
    # Get offerPostID from parameters
    try:
        offerPostID = request.args.get('offerPostID')
    except:
        return "Error getting offer post ID!"
    
    # Query database for offer comments with offerPostID
    offerComments = db.offerComments_collection.find({'offerPostID': offerPostID}).sort('commentTime', pymongo.DESCENDING)

    # Convert offer comments to list
    offerCommentsList = list(offerComments)

    # Convert ObjectId to string
    for offerComment in offerCommentsList:
        offerComment['_id'] = str(offerComment['_id'])

    return jsonify(offerCommentsList)



### Helper functions ###
# Password hashing
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

# Password verification
def compare_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# convert bytes to string
def bytes_to_string(bytes):
    return bytes.decode('utf-8')

# convert string to bytes
def string_to_bytes(string):
    return string.encode('utf-8')

def userProfileInfo(user):
    # Remove password and email from user object if it exists
    if 'hashedPassword' in user:
        del user['hashedPassword']
    if 'email' in user:
        del user['email']

    # convert ObjectId to string
    user['_id'] = str(user['_id'])
    
    return user
    
def get_current_time():
  """Returns the current time in the format YYYY-MM-DDTHH:mm:ss.sssZ."""
  import datetime

  now = datetime.datetime.now()

  date_time = now.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

  return date_time

# if __name__ == '__main__':
#     app.run(port=8000)