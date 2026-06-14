#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

#[account]
pub struct Vault {
    pub balance: u64,
    pub owner: Pubkey,
}

declare_id!("FZqsk1cmkFbbJowGxM3ejY2zf4ieN5uaSLuEqAbUwVSv");

#[program]
pub mod unsafe_arithmetic_fix {
    use super::*;

    pub fn withdraw(ctx: Context<WithdrawSafe>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // --- THE FIX: CHECKED ARITHMETIC ---
        //
        // 1. .checked_sub(amount):
        //    Instead of using the `-` operator, we use a method that returns
        //    an `Option<u64>`.
        //    - If the result is >= 0, it returns `Some(result)`.
        //    - If the result would underflow (e.g., 10 - 11), it returns `None`.
        //
        // 2. .ok_or(CustomError::InsufficientFunds):
        //    This converts the `Option` into a `Result`.
        //    - `Some(val)` becomes `Ok(val)`.
        //    - `None` becomes `Err(CustomError::InsufficientFunds)`.
        //
        // 3. The `?` Operator:
        //    If the result is an `Err`, the `?` immediately exits the function
        //    and returns that error to the Solana runtime.
        //
        // RESULT: The account state is never updated if the math is invalid.
        // The transaction fails, and the attacker gets nothing.
        vault.balance = vault
            .balance
            .checked_sub(amount)
            .ok_or(CustomError::InsufficientFunds)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawSafe<'info> {
    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,
    pub owner: Signer<'info>,
}

#[error_code]
pub enum CustomError {
    // Adding a descriptive error message helps frontend developers
    // and users understand why a transaction was rejected.
    #[msg("The requested withdrawal amount exceeds the vault balance.")]
    InsufficientFunds,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_blocks_underflow_and_allows_valid_withdraw() {
        let vault = Vault {
            balance: 10,
            owner: Pubkey::new_unique(),
        };

        // Underflow should be caught by checked_sub.
        let err = vault
            .balance
            .checked_sub(11)
            .ok_or(CustomError::InsufficientFunds);
        assert!(err.is_err());

        // Valid withdrawal passes.
        let remaining = vault.balance.checked_sub(5).unwrap();
        assert_eq!(remaining, 5);
    }
}
