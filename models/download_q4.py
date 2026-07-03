import os
os.environ["HF_HUB_ENABLE_HF_TRANSFER"] = "0"
from huggingface_hub import hf_hub_download

dest = r"D:\SideProject\models"
print("Downloading Q4_K_M (4.9 GB)...")
path = hf_hub_download(
    "bartowski/Llama-3.1-WhiteRabbitNeo-2-8B-GGUF",
    filename="Llama-3.1-WhiteRabbitNeo-2-8B-Q4_K_M.gguf",
    local_dir=dest
)
print(f"Saved to: {path}")
print(f"Size: {os.path.getsize(path) / 1e9:.2f} GB")
print("Done!")
