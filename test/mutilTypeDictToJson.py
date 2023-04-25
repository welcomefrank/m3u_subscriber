import json

# 不同结构的字典
dict1 = {"a": 1, "b": 2}
dict2 = {"c": {"d": 3, "e": 4}}
dict3 = {"f": [5, 6, 7]}

# 合并字典
merged_dict = {**dict1, **dict2, **dict3}

# 将合并后的字典导出成json字符串
json_string = json.dumps(merged_dict)

# 将json字符串还原成多个字典
restored_dict1 = {}
restored_dict2 = {}
restored_dict3 = {}

for key, value in json.loads(json_string).items():
    if key in dict1:
        restored_dict1[key] = value
    elif key in dict2:
        restored_dict2[key] = value
    elif key in dict3:
        restored_dict3[key] = value

print(restored_dict1)  # 输出: {'a': 1, 'b': 2}
print(restored_dict2)  # 输出: {'c': {'d': 3, 'e': 4}}
print(restored_dict3)  # 输出: {'f': [5, 6, 7]}
