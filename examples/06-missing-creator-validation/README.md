# Missing Creator Validation

## Table of Contents
1. [Introduction](#introduction)
2. [The Vulnerability Explained](#the-vulnerability-explained)
3. [The Attack Scenario](#the-attack-scenario)
4. [Step-by-Step Attack Walkthrough](#step-by-step-attack-walkthrough)
5. [The Fix Explained](#the-fix-explained)
6. [Code Comparison](#code-comparison)
7. [Key Takeaways](#key-takeaways)

---

## Introduction

In Solana, client-side applications specify all the accounts involved in a transaction. This design pattern offers tremendous speed and flexibility, but it shifts the entire security burden to the smart contract developer. 

A **Missing Creator/Authority Validation** vulnerability occurs when a program modifies state or routes funds into a user-specified campaign/fund account without verifying that the account is actually owned by or linked to the expected creator or admin. Without appropriate checks, a compromised frontend or a malicious client transaction can swap the destination accounts, causing users to contribute funds to a completely different campaign.

---

## The Vulnerability Explained

### The Root Cause: Lack of Field Authorization

In the vulnerable version of our crowdfunding program (`example6.rs`), the `contribute` instruction receives a `fund` account typed as a valid `Fund` struct:

```rust
#[derive(Accounts)]
pub struct FundContribute<'info> {
    #[account(mut)]
    pub fund: Account<'info, Fund>,
    
    #[account(mut)]
    pub contributor: Signer<'info>,
    
    // ...
}
```

Anchor automatically performs a **Program Owner Check** (verifying `fund` belongs to this program) and a **Discriminator Check** (verifying it is indeed a `Fund` account structure). 

However, Anchor **does not verify** who created this specific `Fund` account. It does not know if the contributor intended to fund Creator A or Creator B. Anyone can create a `Fund` account using the program. If the contributor tries to donate, an attacker can substitute the `fund` account parameter with their own malicious `Fund` account. The program will execute the transfer of SOL into the attacker's fund, and update the attacker's contribution record.

---

## The Attack Scenario

### Scenario Setup
1. **Creator A (Legitimate Campaign)**: Setup a crowdfunding campaign to build open-source tools.
2. **Creator B (Attacker)**: Setup a clone campaign.
3. **The Victim**: Wants to send 10 SOL to Creator A.

### The Attack Walkthrough
1. The attacker intercepts or alters the transaction arguments (or exploits a frontend bug) to substitute Creator A's `Fund` address with Creator B's `Fund` address.
2. The victim signs the transaction, assuming they are supporting Creator A.
3. The program processes the instruction:
   * Transfers 10 SOL from the victim's wallet to Creator B's `Fund` account.
   * Records the victim's contribution against Creator B's campaign.
4. Creator B successfully claims the SOL from their campaign, stealing the victim's contribution.

---

## The Fix Explained

To prevent this exploit, we bind the `fund` campaign to its `creator` using Anchor's declarative **`has_one`** constraint:

```rust
#[derive(Accounts)]
pub struct FundContributeSafe<'info> {
    #[account(
        mut,
        has_one = creator
    )]
    pub fund: Account<'info, Fund>,

    pub creator: AccountInfo<'info>,
    
    // ...
}
```

### How `has_one` Secures the Program:
1. It reads the `creator` pubkey stored inside the `Fund` state account during deserialization.
2. It verifies that `fund.creator == creator.key()`.
3. It ensures the transaction context contains the expected `creator` account, preventing a mismatch where a user accidentally donates to a campaign owned by a different creator.

---

## Code Comparison

### Vulnerable Code
```rust
#[derive(Accounts)]
pub struct FundContribute<'info> {
    #[account(mut)]
    pub fund: Account<'info, Fund>, // <-- Vulnerable: accepts any valid Fund account
    #[account(mut)]
    pub contributor: Signer<'info>,
}
```

### Secure Code
```rust
#[derive(Accounts)]
pub struct FundContributeSafe<'info> {
    #[account(
        mut,
        has_one = creator // <-- Fix: enforces creator field validation
    )]
    pub fund: Account<'info, Fund>,
    pub creator: AccountInfo<'info>, // <-- Required for has_one check
    #[account(mut)]
    pub contributor: Signer<'info>,
}
```

---

## Key Takeaways

1. **Explicit Authority Checks**: Always verify that state accounts modified by a transaction are owned/authorized by the expected entities.
2. **Use declarative constraints**: Use Anchor's `has_one` constraint to secure fields referencing other accounts (like admin, creator, or owner fields) rather than relying on manual comparison inside the instruction.
