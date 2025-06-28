from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .account_address import AccountAddress


class ApiVersion(Enum):
    V1 = "v1"
    V2 = "v2"
    V3 = "v3"


@dataclass
class GasOptions:
    """
    Gas price options for manipulating how to prioritize transactions.

    The amount of Quants (10^-8 SUPRA) used for a transaction is equal
    to (gas unit price * gas used). The gas_unit_price can be used as a
    multiplier for the amount of Quants willing to be paid for a transaction.
    This will prioritize the transaction with a higher gas unit price.
    """

    gas_unit_price: Optional[int] = None
    """Gas multiplier per unit of gas. Without a value, it will determine 
    the price based on the current estimated price."""

    max_gas: Optional[int] = None
    """Maximum amount of gas units to be used to send this transaction.
    Without a value, it will determine the price based on simulating 
    the current transaction."""

    expiration_secs: int
    # field(default_factory=safe_default_tx_ttl)
    """Number of seconds to expire the transaction from the current local 
    computer time."""


@dataclass
class RestOptions:
    """Options specific to using the REST endpoint."""

    connection_timeout_secs: int
    """Connection timeout in seconds, used for the REST endpoint of the full node."""

    node_api_key: Optional[str] = None
    """Key to use for ratelimiting purposes with the node API. This value will be 
    used as 'Authorization: Bearer <key>'. You may also set this with the 
    NODE_API_KEY environment variable."""

    api_version: ApiVersion = ApiVersion.V3
    """API version to use for requests."""


@dataclass
class PrivateKeyInputOptions:
    """Options for private key input."""

    private_key: Optional[str] = None
    """Private key for signing transactions."""

    private_key_file: Optional[str] = None
    """Path to file containing private key."""


@dataclass
class ProfileAttributeOptions:
    """Options for profile attributes."""

    url: Optional[str] = None
    """REST API URL override."""

    faucet_url: Optional[str] = None
    """Faucet URL override."""


@dataclass
class SupraProfileOptions:
    """
    Profile options for Supra blockchain operations.

    This will be used to override associated settings such as
    the REST URL, the Faucet URL, and the private key arguments.
    Defaults to active profile.
    """

    profile: Optional[str] = None
    """Profile to use from the CLI config."""

    private_key_options: PrivateKeyInputOptions = field(
        default_factory=PrivateKeyInputOptions
    )
    """Private key input options."""

    profile_attribute_options: ProfileAttributeOptions = field(
        default_factory=ProfileAttributeOptions
    )
    """Profile attribute options."""

    sender_account: Optional[AccountAddress] = None
    """Sender account address. This allows you to override the account address 
    from the derived account address in the event that the authentication key 
    was rotated or for a resource account."""


@dataclass
class SupraTransactionOptions:
    """Transaction options for Supra blockchain operations."""

    profile_options: SupraProfileOptions = field(default_factory=SupraProfileOptions)
    """Profile-related options."""

    rest_options: RestOptions = field(default_factory=RestOptions)
    """REST endpoint options."""

    gas_options: GasOptions = field(default_factory=GasOptions)
    """Gas price and limit options."""

    delegation_pool_address: Optional[str] = None
    """Delegation pool address."""
