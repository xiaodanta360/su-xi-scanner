import yara
import hashlib
import os
import shutil

# ========== 配置区 ==========
RULE_PATH = "rules.yar"
QUARANTINE_FOLDER = "./quarantine"
MD5_BLACKLIST = {
    "44d88612fea8a8f36de82e1278abb02f": "EICAR测试病毒样本"
}
SKIP_DIRS = ["/proc", "/sys", "/dev"]
# ============================

if not os.path.exists(QUARANTINE_FOLDER):
    os.mkdir(QUARANTINE_FOLDER)

def get_md5(filepath):
    try:
        h = hashlib.md5()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def quarantine_file(filepath):
    try:
        basename = os.path.basename(filepath)
        dest = os.path.join(QUARANTINE_FOLDER, basename + ".quar")
        shutil.move(filepath, dest)
        print(f"🗃️ 文件已隔离 -> {dest}")
    except Exception as e:
        print(f"❌ 隔离失败：{e}")

def scan_file(filepath, yara_rules):
    print(f"[扫描] {filepath}")
    hit = False
    md5 = get_md5(filepath)
    if md5 and md5 in MD5_BLACKLIST:
        print(f"⚠️ MD5命中！{MD5_BLACKLIST[md5]}")
        hit = True
    if yara_rules:
        matches = yara_rules.match(filepath)
        if matches:
            for m in matches:
                print(f"⚠️ YARA规则命中：{m.rule}")
            hit = True
    if hit:
        opt = input("是否隔离该文件？(y/n): ")
        if opt.lower() == "y":
            quarantine_file(filepath)
    return hit

def scan_path(path, yara_rules):
    if os.path.isfile(path):
        scan_file(path, yara_rules)
        return
    for root, dirs, files in os.walk(path):
        for d in SKIP_DIRS:
            if d in dirs:
                dirs.remove(d)
        for name in files:
            full = os.path.join(root, name)
            scan_file(full, yara_rules)

if __name__ == "__main__":
    rules = None
    if os.path.exists(RULE_PATH):
        try:
            rules = yara.compile(RULE_PATH)
            print("✅ YARA规则加载成功")
        except Exception as e:
            print(f"❌ YARA规则加载失败：{e}")
    else:
        print("ℹ️ 未找到rules.yar，仅使用MD5库扫描")

    target = input("\n请输入要扫描的文件/文件夹路径：")
    if os.path.exists(target):
        scan_path(target, rules)
        print("\n✅ 扫描结束")
    else:
        print("❌ 路径不存在")

