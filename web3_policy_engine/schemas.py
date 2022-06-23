from hexbytes import HexBytes

class Transaction:
    """
    Defines all of the required information for transaction inputs to policy engine
    """

    def __init__(self, to : HexBytes, data : HexBytes, value : int | None = None):
        self.to = to
        self.data = data
        self.value = value