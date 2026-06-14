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

// VULNERABLE: makes an external CPI before updating state and has no
// re-entrancy guard. A malicious CPI target could re-enter this instruction
// within the same transaction and drain funds.
declare_id!("GYy5rDfXMACswfqCFrdNhyCtjrHjLfrwLiv4mcneCXEN");

#[program]
pub mod cpi_reentrancy_vuln {
    use super::*;

    pub fn withdraw(ctx: Context<WithdrawVuln>, amount: u64) -> Result<()> {
        // Capture keys and infos first to avoid borrow conflicts, but still
        // call before state updates (this is the bug).
        let vault_key = ctx.accounts.vault.key();
        let recipient_key = ctx.accounts.recipient.key();
        let victim_program = *ctx.program_id;
        let vault_info = ctx.accounts.vault.to_account_info();
        let recipient_info = ctx.accounts.recipient.to_account_info();
        let attacker_info = ctx.accounts.attacker_program.to_account_info();

        // Now take the mutable borrow for state mutation.
        let vault = &mut ctx.accounts.vault;

        // Call attacker hook before state update (vulnerability enabled).
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
        .ok(); // Continue even if attacker fails (for demo purposes)

        // Sends lamports out before updating state (still vulnerable).
        invoke(
            &system_instruction::transfer(&vault_key, &recipient_key, amount),
            &[vault_info, recipient_info],
        )?;

        vault.balance = vault.balance.saturating_sub(amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawVuln<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
    /// CHECK: simplified recipient for illustration
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
    /// CHECK: the attacker program that will be called
    pub attacker_program: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vuln_allows_stale_write_after_external_call() {
        let authority = Pubkey::new_unique();
        let mut vault = Vault {
            is_locked: false,
            authority,
            balance: 1_000,
        };

        // Simulate attacker reducing balance during CPI before state update.
        let snapshot = vault.balance;
        vault.balance = vault.balance.saturating_sub(500); // nested withdraw
        let final_balance = snapshot.saturating_sub(100); // outer call resumes

        assert_eq!(final_balance, 900);
        assert_eq!(vault.balance, 500); // stale overwrite risk highlighted
    }
}
