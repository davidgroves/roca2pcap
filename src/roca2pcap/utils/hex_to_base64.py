import base64
import sys

if len(sys.argv) < 2:
    print("Usage: hex_to_base64.py <hex_string>")
    sys.exit(1)

hex_string = sys.argv[1]
bytes_obj = bytes.fromhex(hex_string)
base64_string = base64.b64encode(bytes_obj).decode("utf-8")
print("")
print(base64_string)
