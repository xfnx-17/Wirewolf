"""Test if OpenVINO from the build directory can see the NPU."""
import ctypes, os

gui_dir = r"D:\SideProject\build\gui\Release"
dlls = ["tbb12.dll", "openvino.dll", "openvino_c.dll"]

# Try loading the DLLs from the GUI Release directory
os.add_dll_directory(gui_dir)
for d in dlls:
    path = os.path.join(gui_dir, d)
    print(f"{d}: exists={os.path.exists(path)}")

# Check NPU-related DLLs
npu_dlls = ["openvino_intel_npu_plugin.dll", "openvino_intel_npu_compiler.dll"]
for d in npu_dlls:
    path = os.path.join(gui_dir, d)
    print(f"{d}: exists={os.path.exists(path)}, size={os.path.getsize(path)/1e6:.1f}MB" if os.path.exists(path) else f"{d}: MISSING")

# Also check if ze_loader.dll (Level Zero) is available system-wide
import subprocess
result = subprocess.run(["where", "ze_loader.dll"], capture_output=True, text=True)
print(f"\nze_loader.dll (Level Zero): {result.stdout.strip() if result.returncode == 0 else 'NOT FOUND in PATH'}")

# Check if Level Zero DLL exists in System32
ze_path = r"C:\Windows\System32\ze_loader.dll"
print(f"ze_loader.dll in System32: exists={os.path.exists(ze_path)}")
