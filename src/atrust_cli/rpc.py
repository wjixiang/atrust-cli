"""Typed clients for the aTrust internal Thrift RPC services.

Method names, argument field ids and result types mirror the generated
JS clients in resources/app/src/service/thrift/ (shipped unminified).
"""

from __future__ import annotations

from .paths import pipe_path
from .thrift import T_BOOL, T_I32, T_MAP, T_STRING, ThriftPipeClient

STRING = T_STRING
BOOL = T_BOOL
I32 = T_I32
MAP_SS = T_MAP  # map<string,string> — decoded generically

# NOTE: result_type is the thrift type of the success field (field 0).
# T_MAP from GetStatus/GetAllStatus is map<string,string>; the JS layer
# builds it via Thrift.copyMap(success, [null]) with STRING keys/values.


class SdpCoreClient:
    """SdpCoreService — status, config, SPA seed, session lifecycle.

    Served by aTrustAgent (root) over the 'core' named pipe.
    """

    def __init__(self, timeout: float = 3.0) -> None:
        self._c = ThriftPipeClient(pipe_path("core"), "SdpCoreService", timeout)

    def get_status(self, guid: str | None = None) -> dict | None:
        args = {1: (STRING, guid)} if guid else None
        return self._c.call("GetStatus", args, MAP_SS)

    def get_all_status(self, guid: str | None = None) -> dict | None:
        args = {1: (STRING, guid)} if guid else None
        return self._c.call("GetAllStatus", args, MAP_SS)

    def get_spa_info(self, url: str) -> dict | None:
        return self._c.call("GetSpaInfo", {1: (STRING, url)}, MAP_SS)

    def get_sdp_config(self) -> dict | None:
        return self._c.call("GetSdpConfig", None, MAP_SS)

    def query_spa_seed_exist(self, url: str) -> bool | None:
        return self._c.call("QuerySpaSeedExist", {1: (STRING, url)}, BOOL)

    def logout(self, type_: str = "normal", local_send_logout_event: bool = True) -> bool | None:
        return self._c.call(
            "Logout",
            {1: (STRING, type_), 2: (BOOL, local_send_logout_event)},
            BOOL,
        )

    def offline(self) -> bool | None:
        return self._c.call("Offline", None, BOOL)

    def is_rpc_status_normal(self) -> bool | None:
        return self._c.call("IsRpcStatusNormal", None, BOOL)

    def refresh_client_config(self) -> int | None:
        return self._c.call("RefreshClientConfig", None, I32)

    def query_anti_uninstall_main_addr(self) -> str | None:
        return self._c.call("QueryAntiUninstallMainAddr", None, STRING)


class SdpDaemonClient:
    """SdpDaemonService — session monitor registration (served by aTrustAgent)."""

    def __init__(self, timeout: float = 3.0) -> None:
        self._c = ThriftPipeClient(pipe_path("daemon"), "SdpDaemonService", timeout)

    def is_rpc_status_normal(self) -> bool | None:
        return self._c.call("IsRpcStatusNormal", None, BOOL)

    def get_monitor_list(self) -> list | None:
        return self._c.call("GetMonitorList", None, T_MAP)
