#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("5arduqBwbRzWEDyJyFtD1nq8Xyh62nLycGvf31k8eQxm");

#[program]
pub mod transfer_hook_vuln {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let loyalty_points = &mut ctx.accounts.user_loyalty_points;
        loyalty_points.user = ctx.accounts.user.key();
        loyalty_points.points = 0;
        Ok(())
    }

    // Vulnerable Transfer Hook execute callback
    pub fn execute(ctx: Context<TransferHook>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Err(ErrorCode::AmountShouldNotZero.into());
        }

        // Parse owner manually to avoid SPL dependency conflicts
        let source_data = ctx.accounts.source_token.try_borrow_data()?;
        if source_data.len() < 64 {
            return Err(ErrorCode::InvalidTokenAccount.into());
        }
        let owner_in_ata = Pubkey::new_from_array(source_data[32..64].try_into().unwrap());
        if owner_in_ata != ctx.accounts.owner.key() {
            return Err(ErrorCode::InvalidOwner.into());
        }

        // VULNERABILITY: No check on who called this instruction!
        // Anyone can call this instruction directly to mint points for themselves without transferring tokens.
        let loyalty_points = &mut ctx.accounts.loyalty_points;
        loyalty_points.points = loyalty_points
            .points
            .checked_add(amount)
            .ok_or(ErrorCode::Overflow)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        init, 
        payer = user, 
        space = 8 + UserLoyaltyPoints::INIT_SPACE, 
        seeds = [b"user_loyalty_points", user.key().as_ref()], 
        bump
    )]
    pub user_loyalty_points: Account<'info, UserLoyaltyPoints>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct TransferHook<'info> {
    // 1. The Strict Token-2022 Interface (First 4 accounts in order)
    /// CHECK: Validated manually by parsing token account owner
    pub source_token: AccountInfo<'info>,
    /// CHECK: Unused in basic loyalty demonstration
    pub mint: AccountInfo<'info>,
    /// CHECK: Unused in basic loyalty demonstration
    pub destination_token: AccountInfo<'info>,
    /// CHECK: The owner of the source_token
    pub owner: UncheckedAccount<'info>,

    // 2. Custom "Extra" Accounts appended at the end
    #[account(
        mut, 
        seeds = [b"user_loyalty_points", owner.key().as_ref()],
        bump
    )]
    pub loyalty_points: Account<'info, UserLoyaltyPoints>,
}

#[derive(InitSpace)]
#[account]
pub struct UserLoyaltyPoints {
    pub user: Pubkey,
    pub points: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Amount should not be zero")]
    AmountShouldNotZero,
    #[msg("Overflow occurred while adding points")]
    Overflow,
    #[msg("Invalid token account data length")]
    InvalidTokenAccount,
    #[msg("Provided owner does not match the token account owner")]
    InvalidOwner,
}
