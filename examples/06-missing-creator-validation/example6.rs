use anchor_lang::prelude::*;

declare_id!("7tFALhdsgiKWNHh5pmzz9wQ5RJgKKiHcRMcZa1Gz8xFX");

#[program]
pub mod missing_creator_validation_vuln {
    use super::*;

    pub fn contribute(ctx: Context<FundContribute>, amount: u64) -> Result<()> {
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
pub struct FundContribute<'info> {
    // --- STEP 1: LACK OF LOGICAL/AUTHORITY VALIDATION ---
    // BUG: We only mark the 'fund' account as mutable. We do NOT enforce that the 
    // creator of the fund matches any expected creator address. 
    // A malicious actor or frontend bug could supply a Fund account belonging to 
    // a completely different campaign/creator. The contributor's SOL will be transfered 
    // to the wrong fund account, and their contribution state will be recorded against that wrong fund.
    #[account(mut)]
    pub fund: Account<'info, Fund>,

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
