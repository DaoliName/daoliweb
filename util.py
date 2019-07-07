import hashlib


def hash256(data):
    return hashlib.sha256(data).hexdigest()


def secure_filename(s):
    import re
    s = re.sub('[" "\/\--]+', '-', s)
    s = re.sub(r':-', ':', s)
    s = re.sub(r'^-|-$', '', s)
    return s
