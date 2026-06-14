#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("CdviP5RXu72sY5MEuVCnT9c3DoMkBcyfPx7zEPB1s8hY");

#[program]
pub mod transfer_hook_fix {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let loyalty_points = &mut ctx.accounts.user_loyalty_points;
        loyalty_points.user = ctx.accounts.user.key();
        loyalty_points.points = 0;
        Ok(())
    }

    // Secure Transfer Hook execute callback
    pub fn execute(ctx: Context<TransferHook>, amount: u64) -> Result<()> {
        if amount == 0 {
            return Err(ErrorCode::AmountShouldNotZero.into());
        }

        // --- STEP 1: INSTRUCTIONS SYSVAR LOAD ---
        // We load the instructions sysvar account from our context to examine 
        // the transaction execution history.
        let sysvar_info = &ctx.accounts.instructions;

        // --- STEP 2: CPI CALLER VERIFICATION (-1 INDEX) ---
        // Using get_instruction_relative at index -1 retrieves the parent instruction
        // that directly invoked this CPI. During a valid transfer, this is the 
        // Token-2022 program's transfer instruction.
        let parent_instruction = anchor_lang::solana_program::sysvar::instructions::get_instruction_relative(-1, sysvar_info)
            .map_err(|_| ErrorCode::InvalidCaller)?;

        // --- STEP 3: ENFORCE OWNER AUTHORITY ---
        // We define the official Token-2022 Program ID and enforce that the parent 
        // instruction's program_id matches it. This prevents attackers from calling
        // this instruction directly.
        let token_2022_id = Pubkey::new_from_array([
            10, 233, 28, 48, 142, 63, 117, 240, 203, 102, 17, 30, 252, 232, 219, 118, 
            203, 157, 105, 141, 102, 243, 20, 241, 91, 154, 21, 238, 248, 179, 185, 126
        ]);

        if parent_instruction.program_id != token_2022_id {
            return Err(ErrorCode::InvalidCaller.into());
        }

        // --- STEP 4: USER RELATIONSHIP VALIDATION ---
        // Validate that the owner matches the source token account owner
        let source_data = ctx.accounts.source_token.try_borrow_data()?;
        if source_data.len() < 64 {
            return Err(ErrorCode::InvalidTokenAccount.into());
        }
        let owner_in_ata = Pubkey::new_from_array(source_data[32..64].try_into().unwrap());
        if owner_in_ata != ctx.accounts.owner.key() {
            return Err(ErrorCode::InvalidOwner.into());
        }

        // --- STEP 5: MUTATE STATE ---
        let loyalty_points = &mut ctx.accounts.loyalty_points;
        loyalty_points.points = loyalty_points.points
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

    // 3. Instructions Sysvar
    /// CHECK: Inspected using get_instruction_relative to verify caller identity
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions: AccountInfo<'info>,
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
    #[msg("Direct call rejected: Executing program is not the Token-2022 program")]
    InvalidCaller,
}
