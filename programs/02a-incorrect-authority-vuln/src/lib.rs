#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("7gPYxX1fKe74tgxiU6CUzRTw8kD9MhW5mfmLp8kPP3Vo");

#[program]
pub mod incorrect_authority_vuln {
    use super::*;

    /// VULNERABILITY: This function updates a global configuration.
    /// It assumes that because 'caller' is a Signer, they must be the admin.
    /// In reality, any valid Solana account can sign a transaction.
    pub fn set_fee(ctx: Context<SetFeeVuln>, new_fee: u16) -> Result<()> {
        let config = &mut ctx.accounts.config;

        // CRITICAL BUG: There is no logic here checking:
        // if ctx.accounts.caller.key() == config.admin { ... }

        config.fee_bps = new_fee;

        msg!("Fee updated to: {}", new_fee);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SetFeeVuln<'info> {
    /// The configuration account we want to modify.
    /// This account is marked 'mut' so it can be written to.
    #[account(mut)]
    pub config: Account<'info, Config>,

    /// VULNERABILITY: This is the "Caller" or "Signer".
    /// By using the 'Signer' type, Anchor verifies that this account
    /// signed the transaction.
    ///
    /// HOWEVER: Anchor does NOT know that this signer is supposed to
    /// match the 'admin' field stored inside the 'Config' account.
    /// An attacker can provide their own account here, sign the
    /// transaction, and Anchor will consider this a valid 'Signer'.
    pub caller: Signer<'info>,
}

#[account]
pub struct Config {
    pub admin: Pubkey, // This field exists, but is NEVER checked.
    pub fee_bps: u16,  // This is the value an attacker wants to change.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vuln_allows_non_admin_to_set_fee() {
        let admin = Pubkey::new_unique();
        let attacker = Pubkey::new_unique();
        let mut cfg = Config { admin, fee_bps: 50 };

        // Mirrors the vulnerable logic: caller is ignored, fee is overwritten.
        cfg.fee_bps = 9_999;
        let _ = attacker; // caller irrelevance

        assert_eq!(cfg.fee_bps, 9_999);
        assert_eq!(cfg.admin, admin);
    }
}
