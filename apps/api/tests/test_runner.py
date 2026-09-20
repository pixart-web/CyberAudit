from cyberaudit.runner import InMemoryOneTimeExecutionTokens, RunnerCapabilities


def test_execution_token_is_short_lived_job_bound_and_single_use():
    tokens = InMemoryOneTimeExecutionTokens()
    token = tokens.issue("job-a", ttl_seconds=30)
    assert not tokens.consume("job-b", token)
    assert tokens.consume("job-a", token)
    assert not tokens.consume("job-a", token)


def test_runner_contract_denies_generic_capabilities():
    capabilities = RunnerCapabilities()
    assert not capabilities.generic_commands
    assert not capabilities.host_mounts
    assert not capabilities.docker_socket
    assert not capabilities.application_credentials
