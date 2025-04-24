from pymongo import MongoClient

# Connect to MongoDB
client = MongoClient('localhost', 27017)

# Get a list of database names
db_names = client.list_database_names()
print("MongoDB connected successfully!")
print("Databases:", db_names)