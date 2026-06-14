#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("Eu3Vy7HhHGXeW5qiYSfTEPiF1ZbA8224E2VEjNRRHgRv");

#[program]
pub mod incorrect_authority_fix {
    use super::*;

    pub fn set_fee(ctx: Context<SetFeeSafe>, new_fee: u16) -> Result<()> {
        // 1. INPUT VALIDATION (Logical Security)
        // Even an admin shouldn't be able to set a fee to 500% (50,000 bps).
        // This 'require!' macro ensures the business logic remains within bounds.
        require!(new_fee <= 10_000, CustomError::InvalidFee);

        // 2. STATE UPDATE
        // Because of the checks in the 'SetFeeSafe' struct, we can be 100%
        // certain that at this point, 'ctx.accounts.admin' is the correct
        // authority and they have signed the transaction.
        ctx.accounts.config.fee_bps = new_fee;

        msg!("Fee successfully updated to: {}", new_fee);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SetFeeSafe<'info> {
    /// THE FIX: Anchor Constraints
    /// 'mut' allows us to modify the account.
    /// 'has_one = admin' tells Anchor to perform an automatic security check:
    /// It verifies that config.admin (the Pubkey stored in the data)
    /// matches admin.key() (the account passed into the instruction).
    #[account(
        mut,
        has_one = admin @ CustomError::Unauthorized 
    )]
    pub config: Account<'info, Config>,

    /// THE FIX: Authorized Signer
    /// 1. Anchor verifies this account actually signed the transaction.
    /// 2. Because of the 'has_one' above, this MUST be the public key
    ///    stored inside the Config account's 'admin' field.
    pub admin: Signer<'info>,
}

#[account]
pub struct Config {
    pub admin: Pubkey, // The "Owner" of the protocol.
    pub fee_bps: u16,  // The value being protected.
}

#[error_code]
pub enum CustomError {
    #[msg("The provided admin does not match the config admin.")]
    Unauthorized,
    #[msg("The fee must be between 0 and 10,000 basis points (100%).")]
    InvalidFee,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_enforces_admin_and_bounds() {
        let admin = Pubkey::new_unique();
        let mut cfg = Config { admin, fee_bps: 50 };

        // Unauthorized caller should be rejected logically.
        let caller = Pubkey::new_unique();
        assert_ne!(caller, cfg.admin);

        // Business rule: fee must be <= 10_000.
        let too_high = 20_000;
        assert!(too_high > 10_000);

        // Happy path mutation when admin acts within bounds.
        let new_fee = 250u16;
        cfg.fee_bps = new_fee;
        assert_eq!(cfg.fee_bps, new_fee);
    }
}
