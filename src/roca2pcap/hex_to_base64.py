import base64
import sys

hex_string = sys.argv[1]
bytes_obj = bytes.fromhex(hex_string)
base64_string = base64.b64encode(bytes_obj).decode("utf-8")
print("")
print(base64_string)
