#![allow(unexpected_cfgs)]

use anchor_lang::prelude::*;

declare_id!("93PxMvY6TfpdFhMsVN3MzxBkDooKaaVQnCFp7rJRnbWs");

/// # CPI Reentrancy Attacker Program
///
/// This program demonstrates how a malicious external program can exploit reentrancy
/// vulnerabilities in Solana programs that use Cross-Program Invocations (CPI).
///
/// ## The Reentrancy Attack Pattern
///
/// In a reentrancy attack on Solana:
/// 1. Victim program reads state (e.g., `balance = 1000`)
/// 2. Victim program calls external program via CPI (this attacker program)
/// 3. **During the CPI, the attacker gains control of execution**
/// 4. Attacker can:
///    - Inspect victim's account state
///    - Construct a recursive CPI back to the victim
///    - Trigger additional withdrawals while victim's state is stale
/// 5. Control returns to victim program
/// 6. Victim program updates state based on OLD values from step 1
/// 7. **Result: State corruption and fund drainage**
///
/// ## Why This Works (Vulnerable Pattern)
///
/// ```rust
/// // VULNERABLE: Read → CPI → Update
/// pub fn unsafe_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
///     let old_balance = ctx.accounts.vault.balance;  // STEP 1: Read
///     
///     // STEP 2: External call - ATTACKER GAINS CONTROL HERE
///     cpi::notify_external_program(&ctx.accounts.notifier)?;
///     
///     // STEP 3: Update with stale data - TOO LATE!
///     ctx.accounts.vault.balance = old_balance.saturating_sub(amount);
///     Ok(())
/// }
/// ```
///
/// ## How the Attack Exploits This
///
/// **Transaction Timeline:**
/// - T0: User calls `unsafe_withdraw(100)`
/// - T1: Victim reads `balance = 1000`
/// - T2: Victim calls attacker's `reentrancy_hook` via CPI
/// - **T3: ATTACKER EXECUTES (this program runs)**
/// - T4: Attacker inspects victim vault: `balance = 1000` (unchanged)
/// - T5: Attacker constructs CPI back to victim: `unsafe_withdraw(500)`
/// - T6: Victim (inner call) reads `balance = 1000` (still stale!)
/// - T7: Victim (inner call) writes `balance = 500`
/// - T8: Control returns to attacker
/// - T9: Attacker completes `reentrancy_hook`
/// - **T10: Control returns to original `unsafe_withdraw(100)`**
/// - T11: Victim writes `balance = 900` (using T1's stale value)
/// - **RESULT: Withdrew 600 total, but balance only decreased by 100**
///
/// ## Defense Mechanisms (How to Prevent This)
///
/// The fix requires TWO changes:
///
/// 1. **CEI Pattern (Checks-Effects-Interactions):**
///    ```rust
///    // SECURE: Check → Update → CPI
///    pub fn safe_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
///        // CHECKS: Validate inputs
///        require!(amount <= ctx.accounts.vault.balance, ErrorCode::InsufficientBalance);
///        
///        // EFFECTS: Update state BEFORE external call
///        ctx.accounts.vault.balance = ctx.accounts.vault.balance.checked_sub(amount)?;
///        
///        // INTERACTIONS: External call happens last
///        cpi::notify_external_program(&ctx.accounts.notifier)?;
///        Ok(())
///    }
///    ```
///
/// 2. **Reentrancy Guard (Lock Flag):**
///    ```rust
///    #[account]
///    pub struct Vault {
///        pub balance: u64,
///        pub locked: bool,  // Prevents recursive calls
///    }
///    
///    pub fn safe_withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
///        // Check lock
///        require!(!ctx.accounts.vault.locked, ErrorCode::Locked);
///        
///        // Set lock
///        ctx.accounts.vault.locked = true;
///        
///        // Update balance
///        ctx.accounts.vault.balance = ctx.accounts.vault.balance.checked_sub(amount)?;
///        
///        // External call (if attacker tries to re-enter, lock check fails)
///        cpi::notify_external_program(&ctx.accounts.notifier)?;
///        
///        // Release lock
///        ctx.accounts.vault.locked = false;
///        Ok(())
///    }
///    ```
///
/// ## Educational Purpose
///
/// This attacker program is intentionally simplified to demonstrate the CONCEPT
/// of reentrancy attacks. In a real attack:
/// - The attacker would parse victim account data to read balances
/// - The attacker would construct proper CPI instructions back to the victim
/// - The attacker would loop multiple times to maximize drainage
///
/// For this educational repository:
/// - The attack mechanics are documented in code comments
/// - The actual recursive CPI is demonstrated in TypeScript tests
/// - This program serves as the "external notifier" that proves control transfer
#[program]
pub mod cpi_reentrancy_attacker {
    use super::*;

    /// ## Reentrancy Hook Function
    ///
    /// This function is called by the victim program during a CPI.
    /// It represents the moment when the ATTACKER gains control of execution.
    ///
    /// ### What Happens Here:
    ///
    /// 1. **Control Transfer**: The victim program executed `invoke()` or `invoke_signed()`
    ///    to call this function, transferring control to the attacker.
    ///
    /// 2. **State Inspection**: The attacker can now inspect the victim's accounts.
    ///    In a real attack, the attacker would:
    ///    ```rust
    ///    let vault_data = ctx.accounts.victim_vault.try_borrow_data()?;
    ///    let balance = u64::from_le_bytes(vault_data[8..16].try_into().unwrap());
    ///    msg!("Victim balance: {}", balance);  // Still shows OLD value!
    ///    ```
    ///
    /// 3. **Reentrancy Decision**: The attacker determines if re-entry is possible.
    ///    Key questions:
    ///    - Is the victim vault balance still high? (Yes, it hasn't been updated yet)
    ///    - Is there a reentrancy guard? (Check for 'locked' flag)
    ///    - Can we construct a valid CPI back to the victim?
    ///
    /// 4. **Recursive CPI Construction**: If vulnerable, the attacker would construct
    ///    a CPI back to the victim's `withdraw` function:
    ///    ```rust
    ///    // Pseudo-code for recursive CPI:
    ///    // let cpi_accounts = VictimWithdraw {
    ///    //     vault: ctx.accounts.victim_vault.clone(),
    ///    //     user: ctx.accounts.attacker_wallet.clone(),
    ///    //     notifier: ctx.program_id.clone(),  // Call ourselves again!
    ///    // };
    ///    // let cpi_ctx = CpiContext::new(ctx.accounts.victim_program.clone(), cpi_accounts);
    ///    // victim_program::cpi::unsafe_withdraw(cpi_ctx, DRAIN_AMOUNT)?;
    ///    ```
    ///
    /// 5. **State Overwrite**: When control returns to the victim, the victim
    ///    will OVERWRITE the balance we just drained, using its stale `old_balance` value.
    ///
    /// ### Why This Attack Works:
    ///
    /// - Victim reads: `old_balance = 1000`
    /// - Victim calls us (we run this function)
    /// - We withdraw: `balance = 500` (updated on-chain)
    /// - Control returns to victim
    /// - Victim writes: `balance = old_balance - 100 = 900`
    /// - **We withdrew 600, but balance only decreased by 100!**
    ///
    /// ### Why the Fix Works:
    ///
    /// With CEI pattern + reentrancy guard:
    /// - Victim checks: `locked == false` ✓
    /// - Victim sets: `locked = true`
    /// - Victim updates: `balance = 900` (BEFORE calling us)
    /// - Victim calls us (we run this function)
    /// - If we try to re-enter: `locked == true` → **Transaction fails!**
    /// - Even if we bypass the lock somehow, balance is already 900 (not 1000)
    /// - Control returns to victim
    /// - Victim sets: `locked = false`
    ///
    /// ### Educational Note:
    ///
    /// This simplified implementation does NOT actually perform the recursive CPI.
    /// Instead, it:
    /// - Logs that control was transferred (proving the attack vector exists)
    /// - Documents HOW a real attacker would exploit this (in comments)
    /// - Serves as a placeholder for TypeScript tests to demonstrate the full attack
    ///
    /// The actual recursive CPI construction is complex and would require:
    /// - Proper instruction data serialization
    /// - Account meta construction
    /// - Program ID resolution
    /// - Multiple iterations to maximize drainage
    ///
    /// See `scripts/cpi-reentrancy.ts` for the full attack demonstration.
    pub fn reentrancy_hook(_ctx: Context<ReentrancyHook>) -> Result<()> {
        // === STEP 1: ATTACKER GAINS CONTROL ===
        // At this point, the victim program has transferred control to us via CPI.
        // The victim's state update is PENDING (hasn't happened yet).
        msg!("⚔️ Attacker hook called!");
        msg!("🎯 Control transferred from victim to attacker");

        // === STEP 2: STATE INSPECTION (Educational - not implemented) ===
        // In a real attack, we would inspect the victim vault:
        //
        // let vault_data = ctx.accounts.victim_vault.try_borrow_data()?;
        // let current_balance = u64::from_le_bytes(vault_data[8..16].try_into().unwrap());
        //
        // msg!("🔍 Inspecting victim vault state:");
        // msg!("   Current balance: {}", current_balance);
        // msg!("   Expected: Still shows OLD balance (not yet updated)");

        // === STEP 3: REENTRANCY DECISION (Educational - not implemented) ===
        // The attacker would check if re-entry is possible:
        //
        // if current_balance > DRAIN_THRESHOLD {
        //     msg!("💰 Balance is high enough to drain");
        //
        //     // Check for reentrancy guard
        //     let is_locked = vault_data[16]; // Hypothetical lock byte
        //     if is_locked {
        //         msg!("🔒 Reentrancy guard detected - attack blocked!");
        //         return Ok(());
        //     }
        //
        //     msg!("🚨 No reentrancy guard - proceeding with attack");
        // }

        // === STEP 4: RECURSIVE CPI CONSTRUCTION (Educational - not implemented) ===
        // This is where the ACTUAL attack would happen:
        //
        // msg!("🔁 Constructing recursive CPI back to victim...");
        //
        // // Build the CPI accounts
        // let cpi_accounts = VictimWithdraw {
        //     vault: ctx.accounts.victim_vault.to_account_info(),
        //     user: /* attacker's wallet */,
        //     notifier: ctx.program_id.to_account_info(), // Point back to ourselves
        //     system_program: /* ... */,
        // };
        //
        // // Build the CPI context
        // let cpi_ctx = CpiContext::new(
        //     ctx.accounts.victim_program.to_account_info(),
        //     cpi_accounts
        // );
        //
        // // Execute the recursive withdrawal
        // let drain_amount = current_balance / 2; // Take half
        // msg!("💸 Executing recursive withdraw of {} lamports", drain_amount);
        // victim_program::cpi::unsafe_withdraw(cpi_ctx, drain_amount)?;
        //
        // msg!("✅ Recursive CPI completed - funds drained");

        // === STEP 5: RETURN CONTROL TO VICTIM ===
        // When we return Ok(()), control goes back to the victim program.
        // The victim will now OVERWRITE the balance with its stale value.
        msg!("↩️  Returning control to victim");
        msg!("⚠️  Victim will now overwrite balance with stale data");

        // === EDUCATIONAL SUMMARY ===
        // This function demonstrates:
        // 1. ✅ Control flow hijacking (we gained execution during victim's CPI)
        // 2. ✅ State inspection opportunity (we can read victim's accounts)
        // 3. 📚 Recursive CPI construction (documented in comments)
        // 4. 📚 State overwrite vulnerability (explained in comments)
        //
        // For the full attack implementation, see:
        // - scripts/cpi-reentrancy.ts (TypeScript test demonstrating the attack)
        // - examples/04-cpi-reentrancy/README.md (detailed explanation)
        // - SECURITY.md (comprehensive reentrancy documentation)

        Ok(())
    }
}

/// ## Reentrancy Hook Account Context
///
/// This struct defines the accounts that the attacker receives when the victim
/// calls this program via CPI.
///
/// ### Account Roles:
///
/// 1. **victim_vault**: The account the victim is trying to protect
///    - Contains balance and state data
///    - Attacker inspects this to determine if re-entry is profitable
///    - In a real attack, attacker would parse this account's data
///
/// 2. **victim_program**: The program ID of the vulnerable victim
///    - Used to construct recursive CPI calls back to the victim
///    - Allows attacker to invoke victim's functions during the CPI
///
/// ### Why UncheckedAccount?
///
/// These accounts use `AccountInfo` (unchecked) because:
/// - The attacker doesn't know the exact structure of victim's accounts
/// - We want to inspect raw account data without deserialization
/// - This is an ATTACKER program - we're intentionally bypassing safety checks
///
/// ### Account Validation:
///
/// The `/// CHECK:` comments document WHY these accounts are unchecked:
/// - It's not because we FORGOT to validate
/// - It's because we're INTENTIONALLY inspecting arbitrary victim accounts
/// - This pattern is acceptable for attacker/testing programs but NEVER for production
#[derive(Accounts)]
pub struct ReentrancyHook<'info> {
    /// CHECK: Victim vault account that the attacker will inspect
    ///
    /// This account contains the victim's state (balance, locks, etc.).
    /// The attacker inspects this to:
    /// 1. Read current balance (to determine if draining is profitable)
    /// 2. Check for reentrancy guards (locked flag)
    /// 3. Monitor state changes during recursive calls
    ///
    /// Safety: This is an educational attacker program. Using UncheckedAccount
    /// is intentional to demonstrate how attackers inspect arbitrary accounts.
    pub victim_vault: AccountInfo<'info>,

    /// CHECK: Victim program ID for constructing recursive CPI calls
    ///
    /// This is the program ID of the vulnerable victim program.
    /// The attacker uses this to:
    /// 1. Construct CPI context targeting the victim
    /// 2. Invoke victim's withdraw function recursively
    /// 3. Create a reentrancy loop
    ///
    /// Safety: This is an educational attacker program. Using UncheckedAccount
    /// is intentional to demonstrate CPI construction patterns.
    pub victim_program: AccountInfo<'info>,
}
