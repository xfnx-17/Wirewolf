"""
Create a small neural network classifier for the NPU pre-filter.

Input features (3 floats):
  [0] entropy        --Shannon entropy of payload bytes (0.0 - 8.0)
  [1] length_variance --variance of packet lengths in the flow
  [2] inter_arrival   --mean inter-arrival time between packets (seconds)

Output (1 float):
  suspicious probability (0.0 = benign, 1.0 = suspicious)

The model is trained on synthetic data generated from the statistical
filter rules in npu_filter.cpp, so it works out of the box. It can later
be retrained on real labeled network traffic data for better accuracy.
"""

import numpy as np
import openvino as ov
from openvino import Type, Shape, PartialShape
import openvino.opset14 as opset

# ─── Generate synthetic training data ───────────────────────────────

np.random.seed(42)
N = 100000

entropy = np.random.uniform(0.0, 8.0, N).astype(np.float32)
variance = np.random.exponential(20000, N).astype(np.float32)
inter_arrival = np.random.exponential(0.01, N).astype(np.float32)

# Label based on statistical filter rules from npu_filter.cpp
labels = np.zeros(N, dtype=np.float32)

# Rule 1: High entropy (encrypted/obfuscated payloads)
labels[entropy > 7.0] = 1.0

# Rule 2: Low entropy with large implied payload (padding-based exfil)
# We can't check payload size with 3 features, so approximate:
# very low entropy is suspicious on its own
labels[entropy < 1.0] = 1.0

# Rule 3: High packet length variance (scanning/probing)
labels[variance > 50000.0] = 1.0

# Rule 4: Very fast packet rate (flood/DoS)
labels[(inter_arrival < 0.0005) & (inter_arrival > 0.0)] = 1.0

# Add some noise to make the model generalize better
noise_idx = np.random.choice(N, size=int(N * 0.02), replace=False)
labels[noise_idx] = 1.0 - labels[noise_idx]

X = np.stack([entropy, variance, inter_arrival], axis=1)  # (N, 3)
y = labels  # (N,)

print(f"Dataset: {N} samples, {int(y.sum())} suspicious ({y.mean()*100:.1f}%)")

# ─── Build model using OpenVINO opset operations ───────────────────
# Simple 2-layer feedforward: Input(3) ->Dense(16, ReLU) ->Dense(8, ReLU) ->Dense(1, Sigmoid)

def make_constant(name, shape, values):
    return opset.constant(np.array(values, dtype=np.float32).reshape(shape), name=name)

# We'll train with numpy (simple gradient descent) then bake weights into OpenVINO IR

class SimpleNN:
    def __init__(self):
        # Xavier initialization
        self.W1 = np.random.randn(3, 16).astype(np.float32) * np.sqrt(2.0 / 3)
        self.b1 = np.zeros(16, dtype=np.float32)
        self.W2 = np.random.randn(16, 8).astype(np.float32) * np.sqrt(2.0 / 16)
        self.b2 = np.zeros(8, dtype=np.float32)
        self.W3 = np.random.randn(8, 1).astype(np.float32) * np.sqrt(2.0 / 8)
        self.b3 = np.zeros(1, dtype=np.float32)

    def forward(self, X):
        # Normalize inputs to roughly [0,1] range for stable training
        # entropy: /8, variance: /100000, inter_arrival: /0.1
        self.X_norm = X.copy()
        self.X_norm[:, 0] /= 8.0
        self.X_norm[:, 1] /= 100000.0
        self.X_norm[:, 2] /= 0.1

        self.z1 = self.X_norm @ self.W1 + self.b1
        self.a1 = np.maximum(0, self.z1)  # ReLU

        self.z2 = self.a1 @ self.W2 + self.b2
        self.a2 = np.maximum(0, self.z2)  # ReLU

        self.z3 = self.a2 @ self.W3 + self.b3
        self.a3 = 1.0 / (1.0 + np.exp(-np.clip(self.z3, -20, 20)))  # Sigmoid
        return self.a3

    def backward(self, X, y, lr=0.01):
        m = X.shape[0]
        pred = self.forward(X)

        # Binary cross-entropy gradient
        dz3 = (pred - y.reshape(-1, 1)) / m
        dW3 = self.a2.T @ dz3
        db3 = dz3.sum(axis=0)

        da2 = dz3 @ self.W3.T
        dz2 = da2 * (self.z2 > 0).astype(np.float32)
        dW2 = self.a1.T @ dz2
        db2 = dz2.sum(axis=0)

        da1 = dz2 @ self.W2.T
        dz1 = da1 * (self.z1 > 0).astype(np.float32)
        dW1 = self.X_norm.T @ dz1
        db1 = dz1.sum(axis=0)

        # Gradient descent
        self.W3 -= lr * dW3
        self.b3 -= lr * db3
        self.W2 -= lr * dW2
        self.b2 -= lr * db2
        self.W1 -= lr * dW1
        self.b1 -= lr * db1

        # Loss
        eps = 1e-7
        loss = -np.mean(y * np.log(pred.flatten() + eps) +
                       (1 - y) * np.log(1 - pred.flatten() + eps))
        acc = np.mean((pred.flatten() > 0.5) == y)
        return loss, acc


# ─── Train ──────────────────────────────────────────────────────────

print("Training...")
model = SimpleNN()
batch_size = 1024

for epoch in range(50):
    # Shuffle
    idx = np.random.permutation(N)
    X_shuf = X[idx]
    y_shuf = y[idx]

    total_loss = 0
    n_batches = 0
    for i in range(0, N, batch_size):
        Xb = X_shuf[i:i+batch_size]
        yb = y_shuf[i:i+batch_size]
        loss, acc = model.backward(Xb, yb, lr=0.1)
        total_loss += loss
        n_batches += 1

    if (epoch + 1) % 10 == 0:
        pred = model.forward(X)
        acc = np.mean((pred.flatten() > 0.5) == y)
        print(f"  Epoch {epoch+1}: loss={total_loss/n_batches:.4f}, acc={acc*100:.1f}%")

# Final accuracy
pred = model.forward(X)
acc = np.mean((pred.flatten() > 0.5) == y)
print(f"\nFinal accuracy: {acc*100:.1f}%")

# Test specific cases
test_cases = [
    ([7.5, 1000, 0.01], "High entropy (encrypted)"),
    ([0.5, 1000, 0.01], "Low entropy (padding exfil)"),
    ([4.0, 80000, 0.01], "High variance (scanning)"),
    ([4.0, 1000, 0.0001], "Fast packets (flood)"),
    ([4.0, 1000, 0.01], "Normal traffic"),
    ([3.5, 5000, 0.05], "Normal traffic 2"),
]

print("\nTest predictions:")
for features, desc in test_cases:
    inp = np.array([features], dtype=np.float32)
    p = model.forward(inp)[0, 0]
    print(f"  {desc:30s} -> {p:.3f} ({'SUSPICIOUS' if p > 0.5 else 'benign'})")


# ─── Export to OpenVINO IR ──────────────────────────────────────────

print("\nExporting to OpenVINO IR format...")

# Build the OpenVINO model graph with trained weights
# Input: [batch, 3]
param = opset.parameter(Shape([1, 3]), Type.f32, name="features")

# Normalization constants
norm_scale = opset.constant(np.array([1.0/8.0, 1.0/100000.0, 1.0/0.1], dtype=np.float32).reshape(1, 3))
normalized = opset.multiply(param, norm_scale)

# Layer 1: Dense(16) + ReLU
w1 = opset.constant(model.W1.astype(np.float32), name="dense1_weights")
b1 = opset.constant(model.b1.reshape(1, 16).astype(np.float32), name="dense1_bias")
z1 = opset.add(opset.matmul(normalized, w1, False, False), b1)
a1 = opset.relu(z1)

# Layer 2: Dense(8) + ReLU
w2 = opset.constant(model.W2.astype(np.float32), name="dense2_weights")
b2 = opset.constant(model.b2.reshape(1, 8).astype(np.float32), name="dense2_bias")
z2 = opset.add(opset.matmul(a1, w2, False, False), b2)
a2 = opset.relu(z2)

# Layer 3: Dense(1) + Sigmoid
w3 = opset.constant(model.W3.astype(np.float32), name="dense3_weights")
b3 = opset.constant(model.b3.reshape(1, 1).astype(np.float32), name="dense3_bias")
z3 = opset.add(opset.matmul(a2, w3, False, False), b3)
output = opset.sigmoid(z3)

ov_model = ov.Model([output], [param], "wirewolf_npu_filter")

# Verify the model works
core = ov.Core()

# Save as IR (xml + bin)
ov.save_model(ov_model, "D:/SideProject/models/npu_filter.xml")
print("Saved: models/npu_filter.xml + npu_filter.bin")

# Test on CPU
compiled = core.compile_model(ov_model, "CPU")
infer = compiled.create_infer_request()

print("\nVerification (CPU):")
for features, desc in test_cases:
    inp = np.array([features], dtype=np.float32)
    infer.infer({0: inp})
    p = infer.get_output_tensor(0).data[0, 0]
    print(f"  {desc:30s} ->{p:.3f} ({'SUSPICIOUS' if p > 0.5 else 'benign'})")

# Test on NPU if available
if "NPU" in core.available_devices:
    try:
        compiled_npu = core.compile_model(ov_model, "NPU")
        infer_npu = compiled_npu.create_infer_request()
        print("\nVerification (NPU):")
        for features, desc in test_cases:
            inp = np.array([features], dtype=np.float32)
            infer_npu.infer({0: inp})
            p = infer_npu.get_output_tensor(0).data[0, 0]
            print(f"  {desc:30s} ->{p:.3f} ({'SUSPICIOUS' if p > 0.5 else 'benign'})")
        print("\n[OK] NPU inference working!")
    except Exception as e:
        print(f"\nNPU test failed: {e}")
        print("Model will use CPU fallback.")
else:
    print("\nNPU not available, model will use CPU.")

print("\nDone! Model saved to D:/SideProject/models/npu_filter.xml")
