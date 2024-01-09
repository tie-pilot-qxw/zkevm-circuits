import json

print("Line Coverage")
print()

# 递归查找"zkevm-circuits/children/src/children"子目录
def find_src_directory(data):
    if isinstance(data, dict):
        if "zkevm-circuits" in data:
            zkevm_circuits_data = data["zkevm-circuits"]
            if "children" in zkevm_circuits_data:
                children_data = zkevm_circuits_data["children"]
                if "src" in children_data:
                    src_data = children_data["src"]
                    if "children" in src_data:
                        #找到子目录后，计算覆盖率
                        data = src_data["children"]
                        for key,value in data.items():
                            if key.endswith(".rs"):
                                print(key.replace(".rs","")+" module  ==>   ",end="")
                                line_tot = value["linesTotal"]
                                line_covered_tot = value["linesCovered"]
                                if key.replace(".rs","") in data: 
                                    key_without_rs = key.replace(".rs","")
                                    line_tot += data[key_without_rs]["linesTotal"]
                                    line_covered_tot += data[key_without_rs]["linesCovered"]
                                coverage = line_covered_tot / line_tot
                                print("{:.2f}".format(coverage * 100)+"%")

        for key, value in data.items():
            find_src_directory(value)
    elif isinstance(data, list):
        for item in data:
            find_src_directory(item)

# 读取JSON文件
json_file_path = "../target/debug/covdir" 
with open(json_file_path, 'r') as file:
    try:
        json_data = json.load(file)
        find_src_directory(json_data)
    except json.JSONDecodeError:
        print("JSON 文件解析错误")


