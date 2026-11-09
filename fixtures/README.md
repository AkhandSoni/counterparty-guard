# Synthetic scenario inputs

All S1–S10 records are hand-authored, labelled scenario inputs, not chain captures, authenticated accusations or valid payment authorizations. Signature fields use an explicit unsigned placeholder; the demo creates fresh cryptographic signatures at runtime. Sample IDs/code identities are not verification evidence. `expected_signed` and `expected_submitted` are false because no agent transaction is executed. `expected_balance_delta_yocto=0` is the absence of a transfer in this fixture runner, not a measured live account balance.

The runtime uses A’s canonical action schemas and the supported `accept_memo` argument contract. All demo evidence is scoped to sandbox/fixture, even where example account names end in `.testnet`. S8 remains unavailable pending B’s vault/SDK enforcement.
