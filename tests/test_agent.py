import pytest
from atrust_cli.agent import AgentError, wait_for_stable_online, recent_logout_reason


def test_online_pulse_is_rejected():
    now = [0.0]
    class Agent:
        def status(self):
            return {"status": "online" if now[0] < 1 else "logout"}
    with pytest.raises(AgentError, match="offline"):
        wait_for_stable_online(Agent(), clock=lambda: now[0],
                              sleep=lambda n: now.__setitem__(0, now[0] + n))


def test_online_must_remain_stable():
    now = [0.0]
    class Agent:
        def status(self):
            return {"status": "online"}
    wait_for_stable_online(Agent(), clock=lambda: now[0],
                          sleep=lambda n: now.__setitem__(0, now[0] + n))
    assert now[0] == 5


def test_logout_reason_filters_stale_and_unknown(tmp_path, monkeypatch):
    monkeypatch.setattr('atrust_cli.agent.Path.home', lambda: tmp_path)
    log = tmp_path / '.aTrust/logs/aTrustAgent_plugins_aTrustCore_h_e.log'
    log.parent.mkdir(parents=True)
    log.write_text("[2026-11-11 12:45:55.772] Set logout type to 'cookieHijacking' success\n"
                   "[2026-11-11 12:45:56.772] Set logout type to 'secretPayload' success\n")
    assert recent_logout_reason(0) == 'cookieHijacking'
    assert recent_logout_reason(9999999999) is None
