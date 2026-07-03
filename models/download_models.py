import os
os.environ["HF_HUB_ENABLE_HF_TRANSFER"] = "0"

from huggingface_hub import hf_hub_download

dest = r"D:\SideProject\models"

print("Downloading Q6_K (6.6 GB)...")
path1 = hf_hub_download(
    "bartowski/Llama-3.1-WhiteRabbitNeo-2-8B-GGUF",
    filename="Llama-3.1-WhiteRabbitNeo-2-8B-Q6_K.gguf",
    local_dir=dest
)
print(f"Q6_K saved to: {path1}")
print(f"Size: {os.path.getsize(path1) / 1e9:.2f} GB")

print("\nDownloading Q8_0 (8.5 GB)...")
path2 = hf_hub_download(
    "bartowski/Llama-3.1-WhiteRabbitNeo-2-8B-GGUF",
    filename="Llama-3.1-WhiteRabbitNeo-2-8B-Q8_0.gguf",
    local_dir=dest
)
print(f"Q8_0 saved to: {path2}")
print(f"Size: {os.path.getsize(path2) / 1e9:.2f} GB")

print("\nDone!")
