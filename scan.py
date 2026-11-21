import os
import hashlib
try:
    import yara
except ImportError:
    yara = None

# -------------------------- 配置区 --------------------------
RULE_PATH = "rules.yar"
QUARANTINE_DIR = "quarantine"
SKIP_DIRS = {".git", QUARANTINE_DIR, "__pycache__"}
# 测试MD5黑名单
MD5_BLACKLIST = {
    "44d88612fea8a8f36de82e1278abb02": "EICAR测试文件"
}
LOG_FILE = "scan_log.txt"
# -----------------------------------------------------------

if not os.path.exists(QUARANTINE_DIR):
    os.mkdir(QUARANTINE_DIR)

# 加载YARA规则
try:
    rules = yara.compile(filepath=RULE_PATH)
    print("✅ YARA规则加载成功")
except Exception as e:
    print(f"❌ YARA加载失败: {e}")
    exit(1)

def get_md5(file_path):
    try:
        h = hashlib.md5()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def quarantine_file(file_path):
    basename = os.path.basename(file_path)
    new_name = f"{basename}.quar"
    dst = os.path.join(QUARANTINE_DIR, new_name)
    os.rename(file_path, dst)
    print(f"✅ 已隔离至: {dst}")

def scan_path(root_path):
    if not os.path.exists(root_path):
        print("❌ 路径不存在")
        return
    with open(LOG_FILE, "a", encoding="utf-8") as logf:
        for dirpath, dirnames, filenames in os.walk(root_path):
            # 剔除不需要扫描的文件夹
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in filenames:
                fp = os.path.join(dirpath, fname)
                print(f"[扫描] {fp}")
                logf.write(f"SCAN: {fp}\n")
                # MD5检测
                md5 = get_md5(fp)
                if md5 and md5 in MD5_BLACKLIST:
                    msg = f"⚠️ MD5黑名单命中: {MD5_BLACKLIST[md5]}"
                    print(msg)
                    logf.write(msg+"\n")
                    opt = input("是否隔离该文件？(y/n): ")
                    if opt.strip().lower() == "y":
                        quarantine_file(fp)
                # YARA检测
                matches = rules.match(fp)
                if matches:
                    for m in matches:
                        msg = f"⚠️ YARA规则命中: {m.rule}"
                        print(msg)
                        logf.write(msg+"\n")
                        opt = input("是否隔离该文件？(y/n): ")
                        if opt.strip().lower() == "y":
                            quarantine_file(fp)
    print("\n✅ 扫描结束")

if __name__ == "__main__":
    target = input("请输入要扫描的文件/文件夹路径: ").strip()
    scan_path(target)


