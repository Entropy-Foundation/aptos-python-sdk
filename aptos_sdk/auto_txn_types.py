from typing import List

from .bcs import Serializer
from .transactions import EntryFunction

# class ApiVersion(Enum):
#     V1 = "v1"
#     V2 = "v2"
#     V3 = "v3"
#
#
# @dataclass
# class GasOptions:
#     """
#     Gas price options for manipulating how to prioritize transactions.
#
#     The amount of Quants (10^-8 SUPRA) used for a transaction is equal
#     to (gas unit price * gas used). The gas_unit_price can be used as a
#     multiplier for the amount of Quants willing to be paid for a transaction.
#     This will prioritize the transaction with a higher gas unit price.
#     """
#
#     gas_unit_price: Optional[int] = None
#     """Gas multiplier per unit of gas. Without a value, it will determine
#     the price based on the current estimated price."""
#
#     max_gas: Optional[int] = None
#     """Maximum amount of gas units to be used to send this transaction.
#     Without a value, it will determine the price based on simulating
#     the current transaction."""
#
#     expiration_secs: int
#     # field(default_factory=safe_default_tx_ttl)
#     """Number of seconds to expire the transaction from the current local
#     computer time."""
#
#
# @dataclass
# class RestOptions:
#     """Options specific to using the REST endpoint."""
#
#     connection_timeout_secs: int
#     """Connection timeout in seconds, used for the REST endpoint of the full node."""
#
#     node_api_key: Optional[str] = None
#     """Key to use for ratelimiting purposes with the node API. This value will be
#     used as 'Authorization: Bearer <key>'. You may also set this with the
#     NODE_API_KEY environment variable."""
#
#     api_version: ApiVersion = ApiVersion.V3
#     """API version to use for requests."""
#
#
# @dataclass
# class PrivateKeyInputOptions:
#     """Options for private key input."""
#
#     private_key: Optional[str] = None
#     """Private key for signing transactions."""
#
#     private_key_file: Optional[str] = None
#     """Path to file containing private key."""
#
#
# @dataclass
# class ProfileAttributeOptions:
#     """Options for profile attributes."""
#
#     url: Optional[str] = None
#     """REST API URL override."""
#
#     faucet_url: Optional[str] = None
#     """Faucet URL override."""
#
#
# @dataclass
# class SupraProfileOptions:
#     """
#     Profile options for Supra blockchain operations.
#
#     This will be used to override associated settings such as
#     the REST URL, the Faucet URL, and the private key arguments.
#     Defaults to active profile.
#     """
#
#     profile: Optional[str] = None
#     """Profile to use from the CLI config."""
#
#     private_key_options: PrivateKeyInputOptions = field(
#         default_factory=PrivateKeyInputOptions
#     )
#     """Private key input options."""
#
#     profile_attribute_options: ProfileAttributeOptions = field(
#         default_factory=ProfileAttributeOptions
#     )
#     """Profile attribute options."""
#
#     sender_account: Optional[AccountAddress] = None
#     """Sender account address. This allows you to override the account address
#     from the derived account address in the event that the authentication key
#     was rotated or for a resource account."""
#
#
# @dataclass
# class SupraTransactionOptions:
#     """Transaction options for Supra blockchain operations."""
#
#     profile_options: SupraProfileOptions = field(default_factory=SupraProfileOptions)
#     """Profile-related options."""
#
#     rest_options: RestOptions = field(default_factory=RestOptions)
#     """REST endpoint options."""
#
#     gas_options: GasOptions = field(default_factory=GasOptions)
#     """Gas price and limit options."""
#
#     delegation_pool_address: Optional[str] = None
#     """Delegation pool address."""


class AutomationRegistrationPayload:
    """
    Represents an automation registration payload, mirroring the Rust RegistrationParams.
    This is used in TransactionPayload::AutomationRegistration.
    """

    def __init__(
        self,
        payload: EntryFunction,
        task_expiry_time_secs: int,
        task_max_gas_amount: int,
        task_gas_price_cap: int,
        task_automation_fee_cap: int,
        auxiliary_data: List[bytes],
    ):
        self.payload = payload
        self.task_expiry_time_secs = task_expiry_time_secs
        self.task_max_gas_amount = task_max_gas_amount
        self.task_gas_price_cap = task_gas_price_cap
        self.task_automation_fee_cap = task_automation_fee_cap
        self.auxiliary_data = auxiliary_data

    def serialize(self, serializer: Serializer) -> None:
        """Serialize the automation registration payload"""
        # Version (v1 = 1)
        serializer.u8(1)

        # Serialize the entry function payload
        self.payload.serialize(serializer)

        # Serialize other parameters
        serializer.u64(self.task_expiry_time_secs)
        serializer.u64(self.task_max_gas_amount)
        serializer.u64(self.task_gas_price_cap)
        serializer.u64(self.task_automation_fee_cap)

        # Serialize auxiliary data (empty vector)
        serializer.sequence(self.auxiliary_data, Serializer.to_bytes)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, AutomationRegistrationPayload):
            return NotImplemented
        return (
            self.payload == other.payload
            and self.task_expiry_time_secs == other.task_expiry_time_secs
            and self.task_max_gas_amount == other.task_max_gas_amount
            and self.task_gas_price_cap == other.task_gas_price_cap
            and self.task_automation_fee_cap == other.task_automation_fee_cap
            and self.auxiliary_data == other.auxiliary_data
        )

    def __str__(self) -> str:
        return f"AutomationRegistration(payload={self.payload}, expiry={self.task_expiry_time_secs}, max_gas={self.task_max_gas_amount})"
