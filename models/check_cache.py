import os, glob

# Check HF cache
cache = os.path.join(os.path.expanduser("~"), ".cache", "huggingface", "hub")
print(f"Cache dir: {cache}")
print(f"Exists: {os.path.exists(cache)}")

if os.path.exists(cache):
    for d in os.listdir(cache):
        if "bartowski" in d.lower() or "whiterabbit" in d.lower():
            full = os.path.join(cache, d)
            print(f"\nFound: {d}")
            # Check for .incomplete files
            for root, dirs, files in os.walk(full):
                for f in files:
                    fp = os.path.join(root, f)
                    sz = os.path.getsize(fp)
                    if sz > 1024*1024:  # > 1MB
                        print(f"  {f}: {sz/1e9:.2f} GB")

# Also check models dir
models = r"D:\SideProject\models"
for f in os.listdir(models):
    if f.endswith(".gguf"):
        fp = os.path.join(models, f)
        print(f"\nModels dir: {f} = {os.path.getsize(fp)/1e9:.2f} GB")
