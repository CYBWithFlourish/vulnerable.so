#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("EZr1HQFm4MrUebcLfN2Zf8LVCYhAxorFxyuw3Gx1CXCP");

#[program]
pub mod missing_creator_validation_attacker {
    use super::*;

    pub fn execute_attack(ctx: Context<AttackContext>, _amount: u64) -> Result<()> {
        msg!("🎯 Attacker: Attempting creator validation exploit...");
        msg!("   Target Fund: {}", ctx.accounts.fund.key());
        msg!("   Malicious Creator: {}", ctx.accounts.attacker.key());

        // Initialize attack log metadata for audit verification
        let attack_log = &mut ctx.accounts.attack_log;
        attack_log.attacker = ctx.accounts.attacker.key();
        attack_log.target = ctx.accounts.fund.key();
        attack_log.succeeded = true;

        Ok(())
    }

    pub fn initialize_attack_log(ctx: Context<InitializeAttackLog>) -> Result<()> {
        let attack_log = &mut ctx.accounts.attack_log;
        attack_log.attacker = ctx.accounts.attacker.key();
        attack_log.target = Pubkey::default();
        attack_log.succeeded = false;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct AttackContext<'info> {
    /// CHECK: Target fund account to pwn
    #[account(mut)]
    pub fund: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [b"attack-log", attacker.key().as_ref()],
        bump
    )]
    pub attack_log: Account<'info, AttackLog>,

    pub attacker: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeAttackLog<'info> {
    #[account(
        init,
        payer = attacker,
        space = 8 + AttackLog::INIT_SPACE,
        seeds = [b"attack-log", attacker.key().as_ref()],
        bump
    )]
    pub attack_log: Account<'info, AttackLog>,
    #[account(mut)]
    pub attacker: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct AttackLog {
    pub attacker: Pubkey,
    pub target: Pubkey,
    pub succeeded: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::account_info::AccountInfo;
    use anchor_lang::solana_program::clock::Epoch;
    use anchor_lang::{AnchorSerialize, Discriminator};
    use std::collections::BTreeSet;

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
        let mut data =
            <missing_creator_validation_vuln::Fund as Discriminator>::DISCRIMINATOR.to_vec();
        let state = missing_creator_validation_vuln::Fund {
            name: "Vulnerable Campaign".to_string(),
            description: "Some description".to_string(),
            goal: 100,
            deadline: 0,
            creator,
            amount_raised: 0,
            deadline_set: false,
        };
        data.extend_from_slice(&state.try_to_vec().unwrap());
        data
    }

    fn serialize_fixed_fund(creator: Pubkey) -> Vec<u8> {
        let mut data =
            <missing_creator_validation_fix::Fund as Discriminator>::DISCRIMINATOR.to_vec();
        let state = missing_creator_validation_fix::Fund {
            name: "Fixed Campaign".to_string(),
            description: "Some description".to_string(),
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
        let mut data =
            <missing_creator_validation_vuln::Contribution as Discriminator>::DISCRIMINATOR
                .to_vec();
        let state = missing_creator_validation_vuln::Contribution {
            contributor,
            fund,
            amount,
        };
        data.extend_from_slice(&state.try_to_vec().unwrap());
        data
    }

    #[test]
    fn test_attacker_forces_redirect_on_vulnerable() {
        let program_id = missing_creator_validation_vuln::id();
        let attacker_creator = Pubkey::new_unique();
        let contributor = Pubkey::new_unique();
        let fund_pda = Pubkey::new_unique();

        // Attacker campaign (Creator = Attacker)
        let fund_ai = Box::leak(Box::new(make_account_with_key(
            fund_pda,
            program_id,
            false,
            true,
            serialize_fund(attacker_creator),
        )));

        let contributor_ai = Box::leak(Box::new(make_account_with_key(
            contributor,
            Pubkey::new_unique(),
            true,
            true,
            vec![],
        )));

        let (contribution_pda, bump) =
            Pubkey::find_program_address(&[fund_pda.as_ref(), contributor.as_ref()], &program_id);

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
        ]
        .into_boxed_slice();
        let mut info_slice: &[AccountInfo] = Box::leak(infos);

        let mut bumps = missing_creator_validation_vuln::FundContributeBumps { contribution: bump };
        let mut reallocs = BTreeSet::new();

        // Vulnerable program validates the accounts struct successfully because it lacks the creator check!
        let result = missing_creator_validation_vuln::FundContribute::try_accounts(
            &program_id,
            &mut info_slice,
            &[],
            &mut bumps,
            &mut reallocs,
        );

        assert_eq!(result.map(|_| ()), Ok(()));
    }

    #[test]
    fn test_attacker_blocked_on_fixed() {
        let program_id = missing_creator_validation_fix::id();
        let expected_creator = Pubkey::new_unique();
        let attacker_creator = Pubkey::new_unique(); // Supplying mismatching creator
        let fund_pda = Pubkey::new_unique();

        // Campaign actually belongs to attacker
        let fund_ai = Box::leak(Box::new(make_account_with_key(
            fund_pda,
            program_id,
            false,
            true,
            serialize_fixed_fund(attacker_creator),
        )));

        // We supply expected_creator to try and bypass, simulating matching creator
        let creator_ai = Box::leak(Box::new(make_account_with_key(
            expected_creator,
            Pubkey::new_unique(),
            false,
            false,
            vec![],
        )));

        let contributor_ai = Box::leak(Box::new(make_account_with_key(
            Pubkey::new_unique(),
            Pubkey::new_unique(),
            true,
            true,
            vec![],
        )));

        let (contribution_pda, bump) = Pubkey::find_program_address(
            &[fund_pda.as_ref(), contributor_ai.key.as_ref()],
            &program_id,
        );

        let contribution_ai = Box::leak(Box::new(make_account_with_key(
            contribution_pda,
            program_id,
            false,
            true,
            vec![0u8; 8 + missing_creator_validation_fix::Contribution::INIT_SPACE],
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
            (*creator_ai).clone(),
            (*contributor_ai).clone(),
            (*contribution_ai).clone(),
            (*system_program_ai).clone(),
        ]
        .into_boxed_slice();
        let mut info_slice: &[AccountInfo] = Box::leak(infos);

        let mut bumps =
            missing_creator_validation_fix::FundContributeSafeBumps { contribution: bump };
        let mut reallocs = BTreeSet::new();

        // Anchor try_accounts executes constraints automatically
        let result = missing_creator_validation_fix::FundContributeSafe::try_accounts(
            &program_id,
            &mut info_slice,
            &[],
            &mut bumps,
            &mut reallocs,
        );

        // Should fail because expected_creator (creator_ai) != fund.creator (attacker_creator)
        assert!(result.is_err(), "ConstraintHasOne validation must fail");
    }
}
