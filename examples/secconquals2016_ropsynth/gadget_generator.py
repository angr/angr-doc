import random
import base64

all_gadgets = iter(open("gadgets"))

def generate_gadgets():
    return base64.b64decode(next(all_gadgets))
    #return base64.b64decode(open("gadgetlines").readlines()[0])
