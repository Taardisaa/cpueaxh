class CpueaxhError(RuntimeError):
    def __init__(self, code: int, message: str) -> None:
        super().__init__(f"{message} (cpueaxh_err={code})")
        self.code = code
