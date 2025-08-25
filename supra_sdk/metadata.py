import importlib.metadata as metadata

# constants
PACKAGE_NAME = "supra-sdk"


class Metadata:
    """Represents the metadata related to the SDK sent to the rpc_node in header during API call.

    The main objective of this is to provide additional information to the rpc_node to track the source of the incoming
    requests.
    """

    SUPRA_HEADER = "x-supra-client"

    @staticmethod
    def get_supra_header_val():
        version = metadata.version(PACKAGE_NAME)
        return f"supra-python-sdk/{version}"
