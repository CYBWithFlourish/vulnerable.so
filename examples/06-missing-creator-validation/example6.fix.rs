use anchor_lang::prelude::*;

declare_id!("HiSasSPpwvxphdgGsp7iim4CjpYc6CJwY6uUWp9Qqhqc");

#[program]
pub mod missing_creator_validation_fix {
    use super::*;

    pub fn contribute(ctx: Context<FundContributeSafe>, amount: u64) -> Result<()> {
        let fund = &mut ctx.accounts.fund;
        let contribution = &mut ctx.accounts.contribution;

        // Verify deadline is not reached if deadline is set
        if fund.deadline != 0
            && fund.deadline < Clock::get()?.unix_timestamp as u64
        {
            return Err(ErrorCode::DeadlineReached.into());
        }

        // Initialize or update contribution record
        if contribution.contributor == Pubkey::default() {
            contribution.contributor = ctx.accounts.contributor.key();
            contribution.fund = fund.key();
            contribution.amount = 0;
        }

        contribution.amount = contribution
            .amount
            .checked_add(amount)
            .ok_or(ErrorCode::CalculationOverflow)?;

        // Transfer SOL from contributor to fund account
        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.contributor.to_account_info(),
                to: fund.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;

        // Update amount raised in the campaign
        fund.amount_raised = fund
            .amount_raised
            .checked_add(amount)
            .ok_or(ErrorCode::CalculationOverflow)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct FundContributeSafe<'info> {
    // --- STEP 1: CORRECT LOGICAL & AUTHORITY VALIDATION ---
    // FIX: We add `has_one = creator` constraint. This forces Anchor to automatically check 
    // that the `creator` field inside the `Fund` account state matches the `creator` account 
    // passed in this transaction. 
    // If the caller or a compromised frontend attempts to supply a fund belonging to a different creator,
    // Anchor will reject the transaction before it runs, protecting the contributor.
    #[account(
        mut,
        has_one = creator
    )]
    pub fund: Account<'info, Fund>,

    /// CHECK: We pass the creator account as context to verify they match the campaign's creator.
    pub creator: AccountInfo<'info>,

    #[account(mut)]
    pub contributor: Signer<'info>,

    #[account(
        mut,
        seeds = [fund.key().as_ref(), contributor.key().as_ref()],
        bump
    )]
    pub contribution: Account<'info, Contribution>,

    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct Contribution {
    pub contributor: Pubkey,
    pub fund: Pubkey,
    pub amount: u64,
}

#[account]
#[derive(InitSpace)]
pub struct Fund {
    #[max_len(200)]
    pub name: String,
    #[max_len(5000)]
    pub description: String,
    pub goal: u64,
    pub deadline: u64,
    pub creator: Pubkey,
    pub amount_raised: u64,
    pub deadline_set: bool,
}

#[error_code]
pub enum ErrorCode {
    #[msg("Deadline reached")]
    DeadlineReached,
    #[msg("Calculation overflow")]
    CalculationOverflow,
}
