
import json

if __name__ == '__main__':
    s = '{"a": "hey\\n"}\n'
    j = json.loads(s)
    print(j)