import mongoengine as db


db.connect(host="")

class Example(db.Document):
    Target_IP = db.StringField()
    Vendor_name = db.StringField()
    Http_Hash = db.IntField()
    Open_Ports = db.ListField()
    Domains = db.ListField()
    
