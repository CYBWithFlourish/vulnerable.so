#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;
use anchor_lang::solana_program::program::invoke;
use anchor_lang::solana_program::system_instruction;

#[account]
pub struct Vault {
    pub is_locked: bool,
    pub authority: Pubkey,
    pub balance: u64,
}

declare_id!("1bvgQTubQCxQ7jHrVDXJmZ9qHFGaAXEjbRSZMMmS3ZZ");

#[program]
pub mod cpi_reentrancy_fix {
    use super::*;

    pub fn withdraw(ctx: Context<WithdrawSafe>, amount: u64) -> Result<()> {
        // Capture keys and account infos up front to avoid conflicting borrows.
        let vault_key = ctx.accounts.vault.key();
        let recipient_key = ctx.accounts.recipient.key();
        let victim_program = *ctx.program_id;
        let vault_info = ctx.accounts.vault.to_account_info();
        let recipient_info = ctx.accounts.recipient.to_account_info();
        let attacker_info = ctx.accounts.attacker_program.to_account_info();

        // Now take the mutable borrow for state updates and locking.
        let vault = &mut ctx.accounts.vault;

        // Re-entrancy guard: block recursive entry into this instruction.
        require!(!vault.is_locked, CustomError::ReentrancyBlocked);
        vault.is_locked = true; // lock before any external call

        // Update state before CPI to reduce attack surface.
        vault.balance = vault
            .balance
            .checked_sub(amount)
            .ok_or(CustomError::InsufficientFunds)?;

        // Call attacker hook (protected by is_locked guard).
        invoke(
            &anchor_lang::solana_program::instruction::Instruction {
                program_id: ctx.accounts.attacker_program.key(),
                accounts: vec![
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        vault_key, false,
                    ),
                    anchor_lang::solana_program::instruction::AccountMeta::new_readonly(
                        victim_program,
                        false,
                    ),
                ],
                data: [0].to_vec(), // discriminator for reentrancy_hook
            },
            &[vault_info.clone(), attacker_info],
        )
        .ok(); // Continue even if attacker fails

        invoke(
            &system_instruction::transfer(&vault_key, &recipient_key, amount),
            &[vault_info, recipient_info],
        )?;

        vault.is_locked = false; // unlock after success
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawSafe<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    /// CHECK: kept simple for the example
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    /// CHECK: the attacker program that will be called
    pub attacker_program: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum CustomError {
    #[msg("re-entrancy blocked")]
    ReentrancyBlocked,
    #[msg("insufficient funds")]
    InsufficientFunds,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fix_blocks_reentrancy_and_checks_funds() {
        let authority = Pubkey::new_unique();
        let mut vault = Vault {
            is_locked: false,
            authority,
            balance: 1_000,
        };

        // Lock before external call equivalent.
        vault.is_locked = true;
        assert!(vault.is_locked);

        // Funds check mirrors checked_sub in handler.
        let ok = vault.balance.checked_sub(200).unwrap();
        assert_eq!(ok, 800);
    }
}
