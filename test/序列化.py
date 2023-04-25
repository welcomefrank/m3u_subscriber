import json
import redis

r = redis.Redis(host='localhost', port=22772)
my_dict = {"name": "John", "age": 30, "city": "New York"}
outDict = {'urlKey': my_dict}  # 改为使用冒号分隔键和值
# 序列化成JSON字符串
json_string = json.dumps(outDict)

# 将JSON字符串存储到Redis中
r.set("my_dict", json_string)

# 从Redis中读取JSON字符串
json_string_redis = r.get("my_dict")

# 反序列化成Python对象
my_dict_redis = json.loads(json_string_redis)
print(my_dict_redis)