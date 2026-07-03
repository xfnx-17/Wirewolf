import openvino as ov

core = ov.Core()
print("OpenVINO version:", ov.__version__)
print("Available devices:", core.available_devices)

for device in core.available_devices:
    print(f"\n--- {device} ---")
    try:
        print(f"  Full name: {core.get_property(device, 'FULL_DEVICE_NAME')}")
    except Exception:
        pass
