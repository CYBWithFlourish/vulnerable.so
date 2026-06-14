#![allow(unexpected_cfgs)]
use anchor_lang::prelude::*;

#[account]
pub struct MessageBox {
    pub authority: Pubkey,
    pub content: String,
}

declare_id!("Ckqguj7xHrJwoo2DbRhVxco5wpc8soH6WxHgjd1TzN1D");

#[program]
pub mod missing_account_fix {
    use super::*;

    pub fn set_message(ctx: Context<SetMessageSafe>, msg: String) -> Result<()> {
        // --- STEP 1: LOGICAL BOUNDS CHECKING ---
        // Instead of blindly copying slices (which can crash the program),
        // we enforce a business-logic limit. This prevents account data
        // from being cluttered or corrupted by unexpectedly large inputs.
        require!(msg.len() <= 128, CustomError::MessageTooLong);

        // --- STEP 2: TYPE-SAFE FIELD ASSIGNMENT ---
        // Because 'message_box' is now a typed 'Account<MessageBox>', we don't
        // touch raw bytes. We update the 'content' field directly.
        // Anchor handles the serialization (turning this back into bytes)
        // safely and automatically behind the scenes.
        let message_box = &mut ctx.accounts.message_box;
        message_box.content = msg;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct SetMessageSafe<'info> {
    // --- STEP 3: AUTOMATIC TYPE & OWNER VALIDATION ---
    // Using 'Account<'info, MessageBox>' instead of 'AccountInfo' triggers two checks:
    // 1. Discriminator Check: Anchor verifies the first 8 bytes of the account match
    //    the 'MessageBox' type. (Fixes "Type/Discriminator Confusion")
    // 2. Owner Check: Anchor verifies the account is owned by this program.
    //    (Fixes "Ownership Verification" bug)
    #[account(
        mut,
        // --- STEP 4: AUTHORIZATION (has_one) ---
        // This ensures the 'authority' field stored INSIDE the MessageBox account 
        // matches the 'authority' account passed in this transaction.
        // This prevents User A from trying to modify User B's message box.
        has_one = authority,

        // --- STEP 5: ADDRESS IDENTITY (Seeds & Bumps) ---
        // This enforces that the 'message_box' account MUST be a PDA derived from 
        // the string "message" and the authority's public key.
        // BUG FIXED: An attacker cannot pass a "TreasuryConfig" account here 
        // because its address wouldn't match these seeds.
        seeds = [b"message", authority.key().as_ref()],
        bump
    )]
    pub message_box: Account<'info, MessageBox>,

    // --- STEP 6: CRYPTOGRAPHIC SIGNATURE CHECK ---
    // By typing this as 'Signer', Anchor automatically verifies that the
    // transaction was signed by the private key of this account.
    // (Fixes "Lack of Signer Validation" bug)
    pub authority: Signer<'info>,
}

#[error_code]
pub enum CustomError {
    #[msg("message too long")]
    MessageTooLong,
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
            false,
            Epoch::default(),
        )
    }

    fn serialize_message_box(authority: Pubkey, content: &str) -> Vec<u8> {
        let mut data = <MessageBox as Discriminator>::DISCRIMINATOR.to_vec();
        let state = MessageBox {
            authority,
            content: content.to_string(),
        };
        data.extend_from_slice(&state.try_to_vec().unwrap());
        data
    }

    #[test]
    fn safe_rejects_wrong_owner() {
        let program_id = crate::id();
        let authority = Pubkey::new_unique();
        let (pda, _bump) =
            Pubkey::find_program_address(&[b"message", authority.as_ref()], &program_id);

        // Owner does not match program; account construction should fail owner check.
        let message_ai = Box::leak(Box::new(make_account_with_key(
            pda,
            Pubkey::new_unique(),
            false,
            true,
            serialize_message_box(authority, "init"),
        )));

        let result = Account::<MessageBox>::try_from(&*message_ai);
        assert!(result.is_err());
    }

    #[test]
    fn safe_accepts_pda_and_updates_content() {
        let program_id = crate::id();
        let authority = Pubkey::new_unique();
        let (pda, bump) =
            Pubkey::find_program_address(&[b"message", authority.as_ref()], &program_id);

        let message_ai = Box::leak(Box::new(make_account_with_key(
            pda,
            program_id,
            false,
            true,
            serialize_message_box(authority, "init"),
        )));
        let authority_ai = Box::leak(Box::new(make_account_with_key(
            authority,
            Pubkey::new_unique(),
            true,
            false,
            vec![],
        )));

        // Pre-clone infos so we don't hold mutable borrows when building accounts.
        let infos: Vec<AccountInfo<'static>> = vec![(*message_ai).clone(), (*authority_ai).clone()];

        let message_box = Account::<MessageBox>::try_from(&*message_ai).unwrap();
        let signer = Signer::try_from(&*authority_ai).unwrap();

        let mut accounts = SetMessageSafe {
            message_box,
            authority: signer,
        };

        let bumps = SetMessageSafeBumps { message_box: bump };
        let ctx = Context::new(&program_id, &mut accounts, infos.as_slice(), bumps);
        missing_account_fix::set_message(ctx, "hello".to_string()).unwrap();

        assert_eq!(accounts.message_box.content, "hello");
        assert_eq!(accounts.message_box.authority, authority);
    }
}
