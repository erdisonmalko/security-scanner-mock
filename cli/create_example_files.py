import os
from pdb import main
import random
import string

TEST_DIR = "test_files"
os.makedirs(TEST_DIR, exist_ok=True)

def random_bytes(size=1024):
    return bytes(random.getrandbits(8) for _ in range(size))

def random_text(size=512):
    # Include some suspicious keywords
    keywords = ["eval", "exec", "powershell", "rm -rf", "<script>"]
    text = "".join(random.choices(string.ascii_letters + string.digits, k=size))
    # Inject a random keyword
    text += " " + random.choice(keywords)
    return text.encode("utf-8")

# Define files to create
files_to_generate = {
    "safe_document.txt": lambda: b"Hello, this is a safe file for testing.\n" * 5,
    "invoice.pdf.exe": lambda: random_bytes(2048),
    "suspicious_script.py": lambda: random_text(1024),
    "unknown.bin": lambda: random_bytes(4096),
    "payload.scr": lambda: random_text(2048),
}


if __name__ == '__main__':
    for filename, content_fn in files_to_generate.items():
        path = os.path.join(TEST_DIR, filename)
        with open(path, "wb") as f:
            f.write(content_fn())
        print(f"Created test file: {path}")