from cyberaudit.worker import _scope_value_is_private


def test_worker_private_scope_classification():
    assert _scope_value_is_private("10.20.0.0/24")
    assert _scope_value_is_private("127.0.0.1")
    assert not _scope_value_is_private("8.8.8.8")
