import os
libs_dir = r"C:\Users\user\AppData\Roaming\Python\Python314\site-packages\openvino\libs"
for f in sorted(os.listdir(libs_dir)):
    if f.endswith(".dll"):
        size = os.path.getsize(os.path.join(libs_dir, f))
        print(f"{f:55s} {size/1024/1024:8.1f} MB")
