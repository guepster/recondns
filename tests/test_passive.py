# tests/test_passive.py
import types
from recondns.sources import passive

def test_gather_passive_returns_set():
    res = passive.gather_passive("example.com", sources=[])
    assert isinstance(res, set)

# test certspotter/bufferover wrappers exist
def test_functions_exist():
    assert callable(passive.certspotter)
    assert callable(passive.bufferover)
