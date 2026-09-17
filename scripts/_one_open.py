import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from smart_token_prod.stok import open_stok
stok, key = sys.argv[1], sys.argv[2]
open_stok(stok, master_secret=b"wrong-cachegrind", key_path=key)
