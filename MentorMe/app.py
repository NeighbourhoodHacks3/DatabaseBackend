from flask import Flask, request, jsonify, render_template
from markupsafe import escape
from flask_pymongo import pymongo
from bson import ObjectId
import datetime

import bcrypt

import db 

#### MongoDB Atlas backend ####

app = Flask(__name__)

## User database ##
## Create user
# username, email and password are required, hidden in header
@app.route("/user/create")
def create_user():
    # Get username, email and password from parameters
    username = request.args.get('username')
    email = request.args.get('email')
    password = request.args.get('password')

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
def get_user_profile():
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
def update_user():
    # Get username, email and password from parameters
    username = request.args.get('username')
    email = request.args.get('email')
    password = request.args.get('password')

    # First check if user exists
    # Query database for user with username or email
    user = db.users_collection.find_one({'$or': [{'username': username}, {'email': email}]})

    if user:
        # Check if password is correct
        if compare_password(password, user['hashedPassword']):
            # Update other description, jobTitle, and the experience array
            description = request.args.get('description')
            jobTitle = request.args.get('jobTitle')
            experience = request.args.get('experience')

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
def create_request_post():
    # Get userID, title, description, and tags from parameters
    userID = request.args.get('userID')
    title = request.args.get('title')
    description = request.args.get('description')
    tags = request.args.get('tags')
    location = request.args.get('location')
    payment = request.args.get('payment')

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
def get_request_posts():
    # Get page from parameters
    page = int(request.args.get('page'))

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
def update_request_post():
    # Get requestPostID from parameters
    requestPost_id_param = request.args.get('requestPostID')
    requestPostID = ObjectId(requestPost_id_param)

    # Query database for request post with requestPostID
    requestPost = db.requestPosts_collection.find_one({'_id': requestPostID})

    if requestPost:
        # Update request post
        try:
            db.requestPosts_collection.update_one({'_id': requestPost['_id']}, {'$set': {'requestOpen': False}})
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
def create_request_comment():
    # Get userID, requestPostID, and comment from parameters
    userID = request.args.get('userID')
    requestPostID = request.args.get('requestPostID')
    comment = request.args.get('comment')

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
def get_request_comments():
    # Get requestPostID from parameters
    try:
        requestPost_id_param = request.args.get('requestPostID')
    except:
        return "Error getting request post ID!"
    
    requestPostID = ObjectId(requestPost_id_param)

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
def create_offer_post():
    # Get userID, title, description, and tags from parameters
    userID = request.args.get('userID')
    title = request.args.get('title')
    description = request.args.get('description')
    tags = request.args.get('tags')
    location = request.args.get('location')
    payment = request.args.get('payment')

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
def get_offer_posts():
    # Get page from parameters
    page = int(request.args.get('page'))

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
def update_offer_post():
    # Get offerPostID from parameters
    offerPost_id_param = request.args.get('offerPostID')
    offerPostID = ObjectId(offerPost_id_param)

    # Query database for offer post with offerPostID
    offerPost = db.offerPosts_collection.find_one({'_id': offerPostID})

    if offerPost:
        # Update offer post
        try:
            db.offerPosts_collection.update_one({'_id': offerPost['_id']}, {'$set': {'offerOpen': False}})
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
def create_offer_comment():
    # Get userID, offerPostID, and comment from parameters
    userID = request.args.get('userID')
    offerPostID = request.args.get('offerPostID')
    comment = request.args.get('comment')

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
def get_offer_comments():
    # Get offerPostID from parameters
    try:
        offerPost_id_param = request.args.get('offerPostID')
    except:
        return "Error getting offer post ID!"
    
    offerPostID = ObjectId(offerPost_id_param)

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
    if 'password' in user:
        del user['password']
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

if __name__ == '__main__':
    app.run(port=8000)