import asyncio
import time

from supra_sdk.account import Account
from supra_sdk.async_client import ClientConfig, FaucetClient, RestClient
from supra_sdk.bcs import Serializer

from .common import FAUCET_URL, NODE_URL


async def main():
    # Setup client with higher gas limits for automation
    client_config = ClientConfig(
        expiration_ttl=600,
        gas_unit_price=100,
        max_gas_amount=1000000,
    )
    rest_client = RestClient(NODE_URL, client_config)
    faucet_client = FaucetClient(FAUCET_URL, rest_client)

    # Create accounts
    alice = Account.generate()
    bob = Account.generate()

    print("\n=== Addresses ===")
    print(f"Alice: {alice.address()}")
    print(f"Bob: {bob.address()}")

    # Fund accounts
    alice_fund_resp = await faucet_client.faucet(alice.address())
    bob_fund_resp = await faucet_client.faucet(bob.address())
    await asyncio.gather(
        rest_client.wait_for_transaction(alice_fund_resp["Accepted"]),
        rest_client.wait_for_transaction(bob_fund_resp["Accepted"]),
    )

    print("\n=== Initial Setup Complete ===")
    await show_balances(rest_client, alice, bob, "Initial Balances")

    # Register Automation Task
    print("\n=== Registering Automation Task ===")
    account_info = await rest_client.account(alice.address())
    chain_id = await rest_client.chain_id()

    # Prepare transfer parameters
    receiver_bytes = bob.address().address
    amount_serializer = Serializer()
    amount_serializer.u64(1000)
    amount_bytes = amount_serializer.output()

    # Create automation task (transfer 1000 coins from Alice to Bob)
    automation_raw_transaction = rest_client.create_automation_registration_tx_payload_raw_tx_object(
        sender_addr=alice.address(),
        sender_sequence_number=account_info["sequence_number"],
        module_addr="0000000000000000000000000000000000000000000000000000000000000001",
        module_name="supra_account",
        function_name="transfer",
        max_gas_amount=1000000,
        function_type_args=[],
        function_args=[receiver_bytes, amount_bytes],
        automation_max_gas_amount=5000,
        automation_gas_price_cap=100,
        automation_fee_cap_for_epoch=100000000,
        automation_expiration_timestamp_secs=int(time.time()) + 500,
        automation_aux_data=[],
        chain_id=chain_id,
    )

    # Submit automation registration
    registration_result = await rest_client.send_automation_tx_using_raw_transaction(
        sender=alice,
        raw_transaction=automation_raw_transaction,
        enable_transaction_simulation=False,
        enable_wait_for_transaction=True,
    )
    print(f"Automation task registered: {registration_result}")
    await show_balances(rest_client, alice, bob, "After Task Registration")

    # await asyncio.sleep(1)
    print("\n=== Waiting for Automation Task Execution ===")
    print("Waiting 10 seconds to see if automation task executes...")
    await asyncio.sleep(10)

    await show_balances(rest_client, alice, bob, "After Waiting for Execution")

    # Simulate Cancel Task
    print("\n=== Submitting Cancel Task ===")
    try:
        cancel_sim = await rest_client.cancel_automation_task(
            sender=alice, task_index=1, simulate=False
        )
        print(f"Cancel simulation successful: {cancel_sim}")
    except Exception as e:
        print(f"Cancel simulation failed: {e}")

    await show_balances(rest_client, alice, bob, "After Task Cancel")

    await asyncio.sleep(1)

    # Try to Stop Tasks (may fail if already canceled)
    print("\n=== Stopping Tasks ===")
    try:
        stop_result = await rest_client.stop_automation_tasks(
            sender=alice, task_indexes=[1], simulate=False
        )
        print(f"Tasks stopped: {stop_result}")
    except Exception as e:
        print(f"Stop failed (expected if task was already canceled): {e}")

    await show_balances(rest_client, alice, bob, "After Task Stop")

    print("\n=== Automation Example Complete ===")

    await rest_client.close()


async def get_balance(rest_client, account):
    """Get account balance"""
    try:
        return await rest_client.account_balance(account.address())
    except Exception:
        return -1


async def show_balances(rest_client, alice, bob, title):
    """Display balances with title"""
    print(f"\n=== {title} ===")
    alice_balance = await get_balance(rest_client, alice)
    bob_balance = await get_balance(rest_client, bob)
    print(f"Alice: {alice_balance}")
    print(f"Bob: {bob_balance}")


if __name__ == "__main__":
    asyncio.run(main())
