import os
models_dir = r"D:\SideProject\models"
for f in sorted(os.listdir(models_dir)):
    path = os.path.join(models_dir, f)
    if os.path.isfile(path):
        size = os.path.getsize(path)
        print(f"{f:60s} {size/1024/1024:10.1f} MB")
