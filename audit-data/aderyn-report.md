# Aderyn Analysis Report

This report was generated by [Aderyn](https://github.com/Cyfrin/aderyn), a static analysis tool built by [Cyfrin](https://cyfrin.io), a blockchain security company. This report is not a substitute for manual audit or security review. It should not be relied upon for any purpose other than to assist in the identification of potential security vulnerabilities.
# Table of Contents

- [Summary](#summary)
  - [Files Summary](#files-summary)
  - [Files Details](#files-details)
  - [Issue Summary](#issue-summary)
- [High Issues](#high-issues)
  - [H-1: Functions send eth away from contract but performs no checks on any address.](#h-1-functions-send-eth-away-from-contract-but-performs-no-checks-on-any-address)
- [Low Issues](#low-issues)
  - [L-1: Unsafe ERC20 Operations should not be used](#l-1-unsafe-erc20-operations-should-not-be-used)
  - [L-2: Missing checks for `address(0)` when assigning values to address state variables](#l-2-missing-checks-for-address0-when-assigning-values-to-address-state-variables)
  - [L-3: Modifiers invoked only once can be shoe-horned into the function](#l-3-modifiers-invoked-only-once-can-be-shoe-horned-into-the-function)
  - [L-4: State variable could be declared constant](#l-4-state-variable-could-be-declared-constant)


# Summary

## Files Summary

| Key | Value |
| --- | --- |
| .sol Files | 1 |
| Total nSLOC | 129 |


## Files Details

| Filepath | nSLOC |
| --- | --- |
| src/ChristmasDinner.sol | 129 |
| **Total** | **129** |


## Issue Summary

| Category | No. of Issues |
| --- | --- |
| High | 1 |
| Low | 4 |


# High Issues

## H-1: Functions send eth away from contract but performs no checks on any address.

Consider introducing checks for `msg.sender` to ensure the recipient of the money is as intended.

<details><summary>1 Found Instances</summary>


- Found in src/ChristmasDinner.sol [Line: 137](src/ChristmasDinner.sol#L137)

	```solidity
	    function refund() external nonReentrant beforeDeadline {
	```

</details>



# Low Issues

## L-1: Unsafe ERC20 Operations should not be used

ERC20 functions may not behave as expected. For example: return values are not always meaningful. It is recommended to use OpenZeppelin's SafeERC20 library.

<details><summary>1 Found Instances</summary>


- Found in src/ChristmasDinner.sol [Line: 235](src/ChristmasDinner.sol#L235)

	```solidity
	        _to.transfer(refundValue);
	```

</details>



## L-2: Missing checks for `address(0)` when assigning values to address state variables

Check for `address(0)` when assigning values to address state variables.

<details><summary>1 Found Instances</summary>


- Found in src/ChristmasDinner.sol [Line: 171](src/ChristmasDinner.sol#L171)

	```solidity
	        host = _newHost;
	```

</details>



## L-3: Modifiers invoked only once can be shoe-horned into the function



<details><summary>1 Found Instances</summary>


- Found in src/ChristmasDinner.sol [Line: 77](src/ChristmasDinner.sol#L77)

	```solidity
	    modifier nonReentrant() {
	```

</details>



## L-4: State variable could be declared constant

State variables that are not updated following deployment should be declared constant to save gas. Add the `constant` attribute to state variables that never change.

<details><summary>1 Found Instances</summary>


- Found in src/ChristmasDinner.sol [Line: 42](src/ChristmasDinner.sol#L42)

	```solidity
	    bool public deadlineSet = false;
	```

</details>


