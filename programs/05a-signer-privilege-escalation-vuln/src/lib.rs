#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

#[account]
pub struct Settings {
    pub owner: Pubkey, // This field is INTENDED to be the only one allowed to pause.
    pub paused: bool,
}

declare_id!("4kDFeDeUdQ7KWBVr5aqJHN6MCZJ3CTDnbAGqqi9c4naW");

#[program]
pub mod signer_privilege_vuln {
    use super::*;

    pub fn toggle_pause(ctx: Context<TogglePauseVuln>) -> Result<()> {
        // --- VULNERABILITY DETAIL ---
        // At this point, Anchor has only verified:
        // 1. 'settings' is owned by THIS program.
        // 2. 'anyone' actually signed the transaction.
        //
        // It has NOT verified that 'anyone.key()' == 'settings.owner'.
        let settings = &mut ctx.accounts.settings;

        // Because there is no check, ANY user who signs the transaction
        // can reach this line and modify the global protocol state.
        settings.paused = !settings.paused;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct TogglePauseVuln<'info> {
    // [account(mut)] only tells Anchor the account must be writable.
    // It does NOT check the internal data of the account (like the 'owner' field).
    #[account(mut)]
    pub settings: Account<'info, Settings>,

    // 'Signer' only ensures that the transaction was signed by THIS account.
    // An attacker simply provides their own wallet here and signs.
    // Since the program doesn't link 'anyone' to 'settings.owner',
    // the identity of the signer is effectively ignored.
    pub anyone: Signer<'info>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vuln_allows_any_signer_to_toggle() {
        let mut settings = Settings {
            owner: Pubkey::new_unique(),
            paused: false,
        };
        let attacker = Pubkey::new_unique();

        // Mirrors vulnerable behavior: signer identity not checked against owner.
        let _ = attacker;
        settings.paused = !settings.paused;

        assert!(settings.paused);
    }
}
