import importlib.metadata as metadata

# constants
PACKAGE_NAME = "supra-sdk"


class Metadata:
    SUPRA_HEADER = "x-supra-client"

    @staticmethod
    def get_supra_header_val():
        version = metadata.version(PACKAGE_NAME)
        return f"supra-python-sdk/{version}"
