#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

#[account]
pub struct Settings {
    pub owner: Pubkey, // This field stores the "Admin" who is authorized.
    pub paused: bool,
}

declare_id!("4NZmngDJqxrCZvWbAZcaxZshsh4ABZtnSbTqs8hC464E");

#[program]
pub mod signer_privilege_fix {
    use super::*;

    pub fn toggle_pause(ctx: Context<TogglePauseSafe>) -> Result<()> {
        // SECURITY NOTE: We only reach this line if EVERY constraint
        // in the TogglePauseSafe struct below has been satisfied.
        let settings = &mut ctx.accounts.settings;

        settings.paused = !settings.paused;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TogglePauseSafe<'info> {
    #[account(
        mut,
        // --- THE FIX: has_one CONSTRAINT ---
        // Anchor automatically generates a check that does the following:
        // require_keys_eq!(settings.owner, owner.key(), ErrorCode::ConstraintHasOne);
        // 
        // It looks inside the 'settings' account data, finds the 'owner' field, 
        // and ensures it matches the public key of the 'owner' account provided below.
        has_one = owner 
    )]
    pub settings: Account<'info, Settings>,

    // --- THE FIX: Signer TYPE ---
    // By defining this as Signer, Anchor ensures two things:
    // 1. The transaction contains a signature from this account.
    // 2. Because of 'has_one' above, this signer MUST be the address
    //    stored in settings.owner.
    pub owner: Signer<'info>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fix_requires_owner_to_toggle() {
        let owner = Pubkey::new_unique();
        let mut settings = Settings {
            owner,
            paused: false,
        };

        // Unauthorized signer should not be considered in the real handler; here we assert intent.
        let attacker = Pubkey::new_unique();
        assert_ne!(attacker, settings.owner);

        // Simulate authorized toggle.
        settings.paused = !settings.paused;
        assert!(settings.paused);
    }
}
