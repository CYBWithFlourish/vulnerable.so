#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("7tFALhdsgiKWNHh5pmzz9wQ5RJgKKiHcRMcZa1Gz8xFX");

#[program]
pub mod missing_creator_validation_vuln {
    use super::*;

    pub fn contribute(ctx: Context<FundContribute>, amount: u64) -> Result<()> {
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
pub struct FundContribute<'info> {
    // BUG: No creator validation check!
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

    fn serialize_contribution(contributor: Pubkey, fund: Pubkey, amount: u64) -> Vec<u8> {
        let mut data = <Contribution as Discriminator>::DISCRIMINATOR.to_vec();
        let state = Contribution {
            contributor,
            fund,
            amount,
        };
        data.extend_from_slice(&state.try_to_vec().unwrap());
        data
    }

    #[test]
    fn vuln_allows_contributing_to_mismatching_creator() {
        let program_id = crate::id();
        let _creator_a = Pubkey::new_unique();
        let creator_b_attacker = Pubkey::new_unique(); // Attack destination
        
        let fund_pda = Pubkey::new_unique();
        let contributor = Pubkey::new_unique();
        
        // Attacker's fund account (belongs to Creator B)
        let fund_ai = Box::leak(Box::new(make_account_with_key(
            fund_pda,
            program_id,
            false,
            true,
            serialize_fund(creator_b_attacker),
        )));

        let contributor_ai = Box::leak(Box::new(make_account_with_key(
            contributor,
            Pubkey::new_unique(),
            true,
            true,
            vec![],
        )));

        let (contribution_pda, bump) = Pubkey::find_program_address(
            &[fund_pda.as_ref(), contributor.as_ref()],
            &program_id,
        );

        let contribution_ai = Box::leak(Box::new(make_account_with_key(
            contribution_pda,
            program_id,
            false,
            true,
            serialize_contribution(Pubkey::default(), Pubkey::default(), 0),
        )));

        let system_program_ai = Box::leak(Box::new(make_account_with_key(
            anchor_lang::system_program::ID,
            Pubkey::new_unique(),
            false,
            false,
            vec![],
        )));

        let infos: Box<[AccountInfo<'static>]> = vec![
            (*fund_ai).clone(),
            (*contributor_ai).clone(),
            (*contribution_ai).clone(),
            (*system_program_ai).clone(),
        ].into_boxed_slice();
        let mut info_slice: &[AccountInfo] = Box::leak(infos);

        let mut bumps = FundContributeBumps { contribution: bump };
        let mut reallocs = std::collections::BTreeSet::new();

        // VULNERABLE behavior: Successfully validates the accounts struct even with mismatching creator.
        let result = FundContribute::try_accounts(
            &program_id,
            &mut info_slice,
            &[],
            &mut bumps,
            &mut reallocs,
        );

        assert!(result.is_ok(), "Vulnerable program should successfully validate accounts even with mismatching creator");
    }
}
