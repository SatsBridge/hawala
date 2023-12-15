#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod htlc {
    use ink::{
        prelude::{string::String, vec::Vec},
        storage::Mapping,
    };

    #[ink(event)]
    pub struct NewContract {
        #[ink(topic)]
        hash: Hash,
        #[ink(topic)]
        sender: AccountId,
        #[ink(topic)]
        receiver: AccountId,
        amount: Balance,
        timelock: Timestamp,
    }

    #[ink(storage)]
    #[derive(Default)]
    pub struct Htlc {
        contracts: Mapping<
            Hash,
            (
                AccountId, //sender
                AccountId, //receiver
                Balance,   //amount
                Timestamp, //timelock
                bool,      //withdrawn
                bool,      //refunded
                Hash,      //preimage
            ),
        >,
    }

    #[derive(Debug, PartialEq, Eq, scale::Encode, scale::Decode)]
    #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
    pub enum Error {
        /// Returned if the name already exists upon registration.
        ContractAlreadyExists,
        /// Returned if caller is not owner while required to.
        CallerIsNotOwner,
    }

    pub type Result<T> = core::result::Result<T, Error>;

    impl Htlc {
        #[ink(constructor)]
        pub fn new() -> Self {
            let contracts = Mapping::default();
            Self { contracts }
        }

        #[ink(constructor)]
        pub fn default() -> Self {
            let contracts = Mapping::default();
            Self { contracts }
        }

        #[inline]
        fn contracts_impl(&self, hash: Hash) -> bool {
            match self.contracts.get(hash) {
                Some(..) => true,
                _ => false,
            }
        }

        /// Returns the total token supply.
        #[ink(message)]
        pub fn exists(&self, hash: Hash) -> bool {
            match self.contracts.get(hash) {
                Some(..) => true,
                _ => false,
            }
        }

        #[ink(message)]
        pub fn new_contract(
            &mut self,
            sender: AccountId,
            receiver: AccountId,
            amount: Balance,
            hash: Hash,
            timelock: Timestamp,
        ) -> Result<()> {
            // check if contract already exists
            if self.contracts.contains(hash) {
                return Err(Error::ContractAlreadyExists);
            }
            // add new contract
            let contract = (sender, receiver, amount, timelock, false, false, zero_hash());
            self.contracts
                .insert(hash, &contract);

            self.env().emit_event(NewContract {
                hash,
                sender,
                receiver,
                amount,
                timelock,
            });
            Ok(())
        }
    }

    fn zero_address() -> AccountId {
        [0u8; 32].into()
    }

    fn zero_hash() -> Hash {
        [0u8; 32].into()
    }
}
