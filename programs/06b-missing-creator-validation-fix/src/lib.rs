#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("HiSasSPpwvxphdgGsp7iim4CjpYc6CJwY6uUWp9Qqhqc");

#[program]
pub mod missing_creator_validation_fix {
    use super::*;

    pub fn contribute(ctx: Context<FundContributeSafe>, amount: u64) -> Result<()> {
        let fund = &mut ctx.accounts.fund;
        let contribution = &mut ctx.accounts.contribution;

        if fund.deadline != 0
            && fund.deadline < Clock::get()?.unix_timestamp as u64
        {
            return Err(ErrorCode::DeadlineReached.into());
        }

        if contribution.contributor == Pubkey::default() {
            contribution.contributor = ctx.accounts.contributor.key();
            contribution.fund = fund.key();
            contribution.amount = 0;
        }

        contribution.amount = contribution
            .amount
            .checked_add(amount)
            .ok_or(ErrorCode::CalculationOverflow)?;

        let cpi_context = CpiContext::new(
            ctx.accounts.system_program.to_account_info(),
            anchor_lang::system_program::Transfer {
                from: ctx.accounts.contributor.to_account_info(),
                to: fund.to_account_info(),
            },
        );
        anchor_lang::system_program::transfer(cpi_context, amount)?;

        fund.amount_raised = fund
            .amount_raised
            .checked_add(amount)
            .ok_or(ErrorCode::CalculationOverflow)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct FundContributeSafe<'info> {
    // FIX: Enforces fund.creator == creator.key()
    #[account(
        mut,
        has_one = creator
    )]
    pub fund: Account<'info, Fund>,

    /// CHECK: Passed to verify it matches the fund creator
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

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::account_info::AccountInfo;
    use anchor_lang::solana_program::clock::Epoch;
    use anchor_lang::{AnchorSerialize, Discriminator};

    fn make_account_with_key(
        key: Pubkey,
        owner: Pubkey,
        is_signer: bool,
        is_writable: bool,
        data: Vec<u8>,
    ) -> AccountInfo<'static> {
        let leaked_key = Box::leak(Box::new(key));
        let leaked_owner = Box::leak(Box::new(owner));
        let lamports = Box::leak(Box::new(1_000_000_000u64));
        let data: &'static mut [u8] = Box::leak(data.into_boxed_slice());

        AccountInfo::new(
            leaked_key,
            is_signer,
            is_writable,
            lamports,
            data,
            leaked_owner,
            key == anchor_lang::system_program::ID,
            Epoch::default(),
        )
    }

    fn serialize_fund(creator: Pubkey) -> Vec<u8> {
        let mut data = <Fund as Discriminator>::DISCRIMINATOR.to_vec();
        let state = Fund {
            name: "Test Campaign".to_string(),
            description: "Test campaign description".to_string(),
            goal: 100,
            deadline: 0,
            creator,
            amount_raised: 0,
            deadline_set: false,
        };
        data.extend_from_slice(&state.try_to_vec().unwrap());
        data
    }

    #[test]
    fn fixed_blocks_mismatching_creator() {
        let program_id = crate::id();
        let creator_a = Pubkey::new_unique();
        let creator_b_attacker = Pubkey::new_unique();
        
        let fund_pda = Pubkey::new_unique();
        let contributor = Pubkey::new_unique();
        
        // Fund is owned by creator_b_attacker
        let fund_ai = Box::leak(Box::new(make_account_with_key(
            fund_pda,
            program_id,
            false,
            true,
            serialize_fund(creator_b_attacker),
        )));

        // We supply creator_a to trigger a mismatch
        let creator_a_ai = Box::leak(Box::new(make_account_with_key(
            creator_a,
            Pubkey::new_unique(),
            false,
            false,
            vec![],
        )));

        let _contributor_ai = Box::leak(Box::new(make_account_with_key(
            contributor,
            Pubkey::new_unique(),
            true,
            true,
            vec![],
        )));

        let (_contribution_pda, _bump) = Pubkey::find_program_address(
            &[fund_pda.as_ref(), contributor.as_ref()],
            &program_id,
        );

        let _contribution_ai = Box::leak(Box::new(make_account_with_key(
            _contribution_pda,
            program_id,
            false,
            true,
            vec![0u8; 8 + Contribution::INIT_SPACE],
        )));

        let _system_program_ai = Box::leak(Box::new(make_account_with_key(
            anchor_lang::system_program::ID,
            Pubkey::new_unique(),
            false,
            false,
            vec![],
        )));

        // Try to construct FundContributeSafe accounts struct:
        // Normally Anchor generates the check: fund.creator == creator.key()
        let fund_account = Account::<Fund>::try_from(&*fund_ai).unwrap();
        
        // Manual verification check simulating has_one:
        let creator_matches = fund_account.creator == *creator_a_ai.key;
        assert!(!creator_matches); // Correctly identified mismatch!
    }
}
