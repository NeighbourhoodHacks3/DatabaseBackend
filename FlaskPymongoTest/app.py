from flask import Flask
import db

app = Flask(__name__)
@app.route('/')
def flask_mongodb_atlas():
    return "flask mongodb atlas!"
if __name__ == '__main__':
    app.run(port=8000)

#test to insert data to the data base
@app.route("/test")
def test():
    # db.db.collection.insert_one({"name": "John"})
    db.testDB_collection.insert_one({"name": "John"})
    return "Connected to the data base!"