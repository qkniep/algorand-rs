// Copyright (C) 2021 Quentin M. Kniep <hello@quentinkniep.com>
// Distributed under terms of the MIT license.

use crate::{crypto, data::basics};

/*
/// Tests SelfCheckSelected (should always be true, with current testingenv parameters)
/// and then set balance to 0 and test not SelfCheckSelected
fn account_selected() {
    let (sel_params, _, round, addresses, _, vrf_secrets, _, _) = testingenv(t, 100, 2000);
    let period = Period(0);
    let leaders = 0;

    for i in 0..addresses {
        let (ok, record, selection_seed, total_money) = sel_params(addresses[i]);
        assert!(ok, "can't read selection params");
        let sel = AgreementSelector{
            seed: selection_seed,
            round,
            period,
            step: propose,
        };
        let m = Membership {
            record,
            selector:   sel,
            total_money,
        }
        u := MakeCredential(vrfSecrets[i], sel)
        credential, _ := u.Verify(proto, m)
        leaders += credential.Weight
    }

    if leaders < uint64(proto.num_proposers/2) || leaders > uint64(2*proto.NumProposers)) {
        t.Errorf("bad number of leaders %v expected %v", leaders, proto.NumProposers)
    }

    committee := uint64(0)
    step := Soft
    for i, addr := range addresses {
        _, record, selectionSeed, totalMoney := selParams(addr)
        sel := AgreementSelector{
            Seed:   selectionSeed,
            Round:  round,
            Period: period,
            Step:   step,
        }
        m := Membership{
            Record:     record,
            Selector:   sel,
            TotalMoney: totalMoney,
        }
        u := MakeCredential(vrfSecrets[i], sel)
        credential, _ := u.Verify(proto, m)
        committee += credential.Weight
    }

    assert!(committee >= uint64(0.8*float64(step.CommitteeSize(proto))) && committee <= uint64(1.2*float64(step.CommitteeSize(proto))),
        "bad number of committee members {} expected {}", committee, step.committee_size(proto));
}

fn testenv(num_accounts: u32, num_txs: u32) -> (selectionParameterFn, selectionParameterListFn, basics::Round, Vec<basics::Address>, Vec<crypto::SignatureSecrets>, Vec<crypto::VrfKeypair>, Vec<crypto::OTSSecrets>, Vec<transactions::SignedTxn>) {
    testenv_more_keys(num_accounts, numTxs, 5)
}

fn testenv_more_keys(num_accounts: u32, num_txs: u32, key_batches_forward: u32) -> (selectionParameterFn, selectionParameterListFn, basics::Round, Vec<basics::Address>, Vec<crypto::SignatureSecrets>, Vec<crypto::VrfKeypair>, Vec<crypto::OTSSecrets>, Vec<transactions::SignedTxn>) {
    let p = numAccounts;              // n accounts
    let txs = num_txs;                // n txns
    let max_money_at_start = 100_000; // max money start
    let min_money_at_start = 10_000;  // min money start
    let transferred_money = 100;      // max money/txn
    let max_fee = 10;                 // max max_fee/txn
    let e = basics::Round(50);        // max round

    // generate accounts
    let genesis := make(map[basics.Address]basics.AccountData)
    let gen := rand.New(rand.NewSource(2))
    let addrs := make([]basics.Address, P)
    let secrets := make([]*crypto.SignatureSecrets, P)
    let vrfSecrets := make([]*crypto.VrfPrivkey, P)
    let otSecrets := make([]*crypto.OneTimeSignatureSecrets, P)
    let proto := config.Consensus[protocol.ConsensusCurrentVersion]
    let lookback := basics.Round(2*proto.SeedRefreshInterval + proto.SeedLookback + 1)
    let mut total = basics::MicroAlgos(0);
    for i := 0; i < P; i++ {
        addr, sigSec, vrfSec, otSec := newAccount(t, gen, lookback, keyBatchesForward)
        addrs[i] = addr
        secrets[i] = sigSec
        vrfSecrets[i] = vrfSec
        otSecrets[i] = otSec

        startamt := uint64(minMoneyAtStart + (gen.Int() % (maxMoneyAtStart - minMoneyAtStart)))
        short := addr
        genesis[short] = basics.AccountData{
            Status:      basics.Online,
            MicroAlgos:  basics.MicroAlgos{Raw: startamt},
            SelectionID: vrfSec.Pubkey(),
            VoteID:      otSec.OneTimeSignatureVerifier,
        }
        total += startamt
    }

    var seed Seed
    rand.Read(seed[:])

    tx := make([]transactions.SignedTxn, TXs)
    for i := 0; i < TXs; i++ {
        send := gen.Int() % P
        recv := gen.Int() % P

        saddr := addrs[send]
        raddr := addrs[recv]
        amt := basics.MicroAlgos{Raw: uint64(gen.Int() % transferredMoney)}
        fee := basics.MicroAlgos{Raw: uint64(gen.Int() % maxFee)}

        t := transactions.Transaction{
            Type: protocol.PaymentTx,
            Header: transactions.Header{
                Sender:     saddr,
                Fee:        fee,
                FirstValid: 0,
                LastValid:  E,
                Note:       make([]byte, 4),
            },
            PaymentTxnFields: transactions.PaymentTxnFields{
                Receiver: raddr,
                Amount:   amt,
            },
        }
        rand.Read(t.Note)
        tx[i] = t.Sign(secrets[send])
    }

    selParams := func(addr basics.Address) (bool, BalanceRecord, Seed, basics.MicroAlgos) {
        data, ok := genesis[addr]
        if !ok {
            return false, BalanceRecord{}, Seed{}, basics.MicroAlgos{Raw: 0}
        }
        return true, BalanceRecord{Addr: addr, OnlineAccountData: data.OnlineAccountData()}, seed, total
    }

    selParamsList := func(addrs []basics.Address) (ok bool, records []BalanceRecord, seed Seed, total basics.MicroAlgos) {
        records = make([]BalanceRecord, len(addrs))
        for i, addr := range addrs {
            var record BalanceRecord
            ok, record, seed, total = selParams(addr)
            if !ok {
                return false, nil, Seed{}, basics.MicroAlgos{Raw: 0}
            }
            records[i] = record
        }
        ok = true
        return
    }

    return selParams, selParamsList, lookback, addrs, secrets, vrfSecrets, otSecrets, tx
}
*/
