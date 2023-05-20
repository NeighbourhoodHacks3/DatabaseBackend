from flask import Flask
from flask_pymongo import pymongo
from hidden import CONNECTION_STRING

# Create connection straing
client = pymongo.MongoClient(CONNECTION_STRING)
db = client.get_database('nhthree')
testDB_collection = pymongo.collection.Collection(db, 'testDB')