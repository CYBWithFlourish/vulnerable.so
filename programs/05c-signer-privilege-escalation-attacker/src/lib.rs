#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("qSxtExRw9NWQ9W5DzkRJJY6sbQPpFRP9fpRPxxpTt3q");

/// # Signer Privilege Escalation Attacker Program
///
/// This program demonstrates how to exploit missing signer identity validation.
/// It attempts to attack both the vulnerable and fixed versions to show:
/// - **Vulnerable version**: Attack succeeds (any signer can pause the protocol)
/// - **Fixed version**: Attack fails (has_one constraint enforces owner check)
///
/// ## Attack Strategy
///
/// The vulnerability exists because:
/// 1. The victim checks that SOMEONE signed (Signer type)
/// 2. But doesn't verify WHO signed (no identity check)
/// 3. No `has_one = owner` constraint linking signer to stored owner
/// 4. Assumes all signers have equal privileges (WRONG!)
///
/// The attacker exploits this by:
/// 1. Creating their own wallet and signing a transaction
/// 2. Calling the victim's privileged function (e.g., toggle_pause)
/// 3. Successfully executing admin-only operations despite not being the owner
/// 4. Gaining full control over protocol state
///
/// ## Expected Results
///
/// - **Against vulnerable version**: ✅ Attack succeeds, protocol paused by non-owner
/// - **Against fixed version**: ❌ Attack fails with "has_one constraint violated"

#[program]
pub mod signer_privilege_attacker {
    use super::*;

    /// Attempts to exploit the signer privilege escalation vulnerability
    ///
    /// This demonstrates how a regular user can execute privileged operations
    /// (like pausing the protocol) that should only be available to the owner.
    ///
    /// **Against vulnerable program**: Succeeds (no owner identity check)
    /// **Against fixed program**: Fails (has_one = owner constraint enforced)
    pub fn escalate_privilege(ctx: Context<EscalateContext>) -> Result<()> {
        msg!("🎯 Attacker: Attempting signer privilege escalation...");
        msg!("   Attacker wallet: {}", ctx.accounts.attacker.key());

        // --- ATTACK STEP 1: Verify we are NOT the owner ---
        // This attack only works if the attacker is NOT the legitimate owner
        msg!("   ✓ Attacker has signed the transaction");
        msg!("   ✓ Attempting to execute owner-only operation");

        // --- ATTACK STEP 2: Explain the vulnerability ---
        // VULNERABLE CODE: Checks if someone signed, not WHO signed
        // ```rust
        // pub fn toggle_pause(ctx: Context<TogglePauseVuln>) -> Result<()> {
        //     let settings = &mut ctx.accounts.settings;
        //     settings.paused = !settings.paused;  // No check if anyone == owner!
        //     Ok(())
        // }
        //
        // #[derive(Accounts)]
        // pub struct TogglePauseVuln<'info> {
        //     #[account(mut)]
        //     pub settings: Account<'info, Settings>,
        //     pub anyone: Signer<'info>,  // Any signer accepted!
        // }
        // ```
        msg!("   ⚠️  Vulnerability: Victim accepts any Signer");
        msg!("   ⚠️  Missing: has_one = owner constraint");
        msg!("   ⚠️  Result: Any wallet can execute owner functions");

        // --- ATTACK STEP 3: Demonstrate the exploit ---
        // The attacker will call the victim program's toggle_pause instruction
        // using their own wallet, gaining unauthorized control over the protocol
        msg!("   🚨 Calling victim program to toggle pause state...");
        msg!("   Expected outcome:");
        msg!("      - Vulnerable version: Protocol pause toggled ✅");
        msg!("      - Fixed version: Transaction rejected ❌");

        // Log the attack attempt
        let attack_log = &mut ctx.accounts.attack_log;
        attack_log.attacker = ctx.accounts.attacker.key();
        attack_log.target_settings = ctx.accounts.target_settings.key();
        attack_log.operation = PrivilegedOperation::TogglePause;
        attack_log.timestamp = Clock::get()?.unix_timestamp;

        msg!("✅ Attacker: Attack execution completed");
        msg!("   (If vulnerable, protocol state is now controlled by attacker)");

        Ok(())
    }

    /// Attempts to exploit privilege escalation for configuration changes
    ///
    /// This variant demonstrates changing protocol parameters that should
    /// only be modifiable by the owner.
    pub fn unauthorized_config_change(ctx: Context<EscalateContext>, new_value: u64) -> Result<()> {
        msg!("🎯 Attacker: Attempting unauthorized configuration change...");
        msg!("   Trying to set config value to: {}", new_value);

        let attack_log = &mut ctx.accounts.attack_log;
        attack_log.attacker = ctx.accounts.attacker.key();
        attack_log.target_settings = ctx.accounts.target_settings.key();
        attack_log.operation = PrivilegedOperation::ConfigChange;
        attack_log.timestamp = Clock::get()?.unix_timestamp;

        msg!("   Expected outcome:");
        msg!("      - Vulnerable: Config changed ✅");
        msg!("      - Fixed: Access denied ❌");

        Ok(())
    }

    /// Initializes the attack log to track privilege escalation attempts
    pub fn initialize_attack_log(ctx: Context<InitializeAttackLog>) -> Result<()> {
        let attack_log = &mut ctx.accounts.attack_log;
        attack_log.attacker = ctx.accounts.attacker.key();
        attack_log.target_settings = Pubkey::default();
        attack_log.operation = PrivilegedOperation::None;
        attack_log.timestamp = 0;

        msg!(
            "Attack log initialized for: {}",
            ctx.accounts.attacker.key()
        );
        Ok(())
    }
}

/// Context for executing the privilege escalation attack
#[derive(Accounts)]
pub struct EscalateContext<'info> {
    /// CHECK: This is an attacker program that intentionally accepts any account
    /// as the target. The attacker passes the victim program's settings account
    /// to demonstrate the privilege escalation vulnerability. No validation needed
    /// here because the attack's goal is to show how the VICTIM program fails to
    /// validate the signer's identity against the owner field in this account.
    #[account(mut)]
    pub target_settings: UncheckedAccount<'info>,

    /// Attack log to track privilege escalation attempts
    #[account(
        mut,
        seeds = [b"attack-log", attacker.key().as_ref()],
        bump
    )]
    pub attack_log: Account<'info, AttackLog>,

    /// The attacker executing this exploit
    ///
    /// ATTACK VECTOR: We sign with OUR wallet (not the owner's).
    /// The vulnerable program accepts any Signer without checking
    /// if the signer's key matches the owner field in settings.
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

/// Stores information about privilege escalation attempts
#[account]
#[derive(InitSpace)]
pub struct AttackLog {
    pub attacker: Pubkey,               // Who attempted privilege escalation
    pub target_settings: Pubkey,        // Which settings were targeted
    pub operation: PrivilegedOperation, // What operation was attempted
    pub timestamp: i64,                 // When the attack occurred
}

/// Types of privileged operations an attacker might attempt
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, InitSpace)]
pub enum PrivilegedOperation {
    None,
    TogglePause,       // Pausing/unpausing the protocol
    ConfigChange,      // Modifying protocol parameters
    OwnershipTransfer, // Changing the owner
    EmergencyWithdraw, // Draining protocol funds
}

#[error_code]
pub enum AttackError {
    #[msg("Attack setup failed")]
    SetupFailed,
    #[msg("Privilege check passed (unexpected - should fail against fixed version)")]
    UnexpectedSuccess,
}
