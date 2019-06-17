// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 Bitcoin developers
// Copyright (c) 2014-2015 Dash developers
// Copyright (c) 2015-2018 PIVX developers
// Copyright (c) 2018-2019 SwiftCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "random.h"
#include "util.h"
#include "utilstrencodings.h"

#include <assert.h>

#include <boost/assign/list_of.hpp>

using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with timestamp before)
// + Contains no strange transactions
static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of
    (0,       uint256("0x000001211fb1c1d0cf722e8934ecc1d6dac522e0489657a8cd6b5ea288f8729b"))
    (10,      uint256("0x68b1ddc4e1057bc4123d68e50aa6cbfefd2caa7d10d72f2bdfa017bcfe3d3a9e"))
    (20,      uint256("0x01174ff22cce79c860d5e24c2b4936271bd2618618a7f3259c66ebd7106da4a3"))
    (30,      uint256("0x2ff7d0fbe54c69ec3f584e8d12abb85413ccdcb1f6c73b329a3c36b9281b9eea"))
    (40,      uint256("0x4285ae38dc37825f1863259f12d61d61fd07ee76c2d935892fd1bf1f256ab355"))
    (50,      uint256("0x70a22f356b8a41b138c02f2b2a167de3e9093b6b02d71ac2429a82c1893cf0fd"))
    (80,      uint256("0x1cc05d9d8d33d5cb67394c1490ccd284e37d595b5077d3fc83770991272aa955"))
    (1000,    uint256("0x55804b4aa442d255032b8380a401f35b5d8284eb772a208f87fa26077c6e4770"))
    (50000,   uint256("0xb164f28990656cd6fced3b38122dbac0beea44d526aa8484e7b1e1da152c1ce5"))
    (100000,  uint256("0x08da181c548eceedc0bdd98d601f1e10574a2d534277be5282de80ae7b10da5c"))
    (120000,  uint256("0x598471acd2cde58b6ab4da1a1c9a9f139075b8e225e1a370ea6edb1b594cb44e"));


static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1557281089, // * UNIX timestamp of last checkpoint block
    243128, 	// * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    250         // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0x001"));

static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    1540687444,
    0,
    250};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x001"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    1540687443,
    0,
    100};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x42;
        pchMessageStart[1] = 0x1e;
        pchMessageStart[2] = 0x31;
        pchMessageStart[3] = 0xf5;
        vAlertPubKey = ParseHex("03001a39c631d98c9a674d1c855efd7f6cc2a893bf7e8f71f70f5ea4d06c679bc6");
        nDefaultPort = 8544;
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        nSubsidyHalvingInterval = 1050000;
        nMaxReorganizationDepth = 100;
        nEnforceBlockUpgradeMajority = 8100; // 75%
        nRejectBlockOutdatedMajority = 10260; // 95%
        nToCheckBlockUpgradeMajority = 10800; // Approximate expected amount of blocks in 7 days (1440*7.5)
        nMinerThreads = 0;
        nTargetTimespan = 40 * 60; // SwiftCash: 40 minutes
        nTargetSpacing = 1 * 60;  // SwiftCash: 1 minute
        nRetargetInterval = 1; // SwiftCash: each block
        nMaturity = 20;
        nSwiftnodeCountDrift = 20;
        nMaxMoneyOut = 5000000000 * COIN; // 5B

        /** Height or Time Based Activations **/
        nLastPOWBlock = 200;
        nModifierUpdateBlock = 1; // we use the version 2 for SWIFT

        /**
         * Build the genesis block. Note that the output of the genesis coinbase cannot
         * be spent as it did not originally exist in the database.
         * node genesis.js -a keccak -t 1540687441 -v 0 -n 21256600 -z "Shooting at Tree of Life Congregation Synagogue in Pittsburgh"
         * ---------------
         * algorithm: keccak
         * pzTimestamp: Shooting at Tree of Life Congregation Synagogue in Pittsburgh
         * pubkey: 04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f
         * bits: 504365040
         * time: 1540687441
         * merkle root hash: 28d9b3039993f5d90fda19141eaddc8b4459710bd752e41b6e23388ae5726c26
         * Searching for genesis hash...
         * nonce: 21766572
         * genesis hash: 000001211fb1c1d0cf722e8934ecc1d6dac522e0489657a8cd6b5ea288f8729b
         */
        const char* pszTimestamp = "Shooting at Tree of Life Congregation Synagogue in Pittsburgh";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1540687441;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 21766572;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x000001211fb1c1d0cf722e8934ecc1d6dac522e0489657a8cd6b5ea288f8729b"));
        assert(genesis.hashMerkleRoot == uint256("0x28d9b3039993f5d90fda19141eaddc8b4459710bd752e41b6e23388ae5726c26"));

        // DNS Seeding
        vSeeds.push_back(CDNSSeedData("seed1.swiftcash.cc", "seed1.swiftcash.cc"));
        vSeeds.push_back(CDNSSeedData("seed2.swiftcash.cc", "seed2.swiftcash.cc"));
        vSeeds.push_back(CDNSSeedData("seed3.swiftcash.cc", "seed3.swiftcash.cc"));

        vSeeds.push_back(CDNSSeedData("seed1.swiftcash.space", "seed1.swiftcash.space"));
        vSeeds.push_back(CDNSSeedData("seed2.swiftcash.space", "seed2.swiftcash.space"));
        vSeeds.push_back(CDNSSeedData("seed3.swiftcash.space", "seed3.swiftcash.space"));

        // SwiftCash addresses start with 'S'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 63);
        // SwiftCash script addresses start with '8'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 18);
        // SwiftCash private keys start with 'V'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 191);
        // SwiftCash BIP32 pubkeys start with 'xpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        // SwiftCash BIP32 prvkeys start with 'xprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // SwiftCash BIP44 coin type is '335' (0x8000014f)
        // BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x01)(0x4f).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "03ae4c8038c50e10015d436f938237d66d7c8da21ee1a989658424cfe60379da78";
        strSwiftnodePoolDummyAddress = "Sh7nUAg9fWxqhCL2KiqWarsF6VfPBPvJz4";

        nBudget_Fee_Confirmations = 6; // Number of confirmations for the finalization fee
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0x42;
        pchMessageStart[1] = 0x51;
        pchMessageStart[2] = 0xd3;
        pchMessageStart[3] = 0x8a;
        vAlertPubKey = ParseHex("02c1d175e8a526d9ee25770b7b3d3a4f850f00b611130c2e07c1682aa3a74d5436");
        nDefaultPort = 28544;
        nEnforceBlockUpgradeMajority = 4320; // 75%
        nRejectBlockOutdatedMajority = 5472; // 95%
        nToCheckBlockUpgradeMajority = 5760; // 4 days
        nMinerThreads = 0;
        nTargetTimespan = 40 * 60; // SwiftCash: 40 minutes
        nTargetSpacing = 1 * 60; // SwiftCash: 1 minute
        nRetargetInterval = 1; // SwiftCash: each block
        nLastPOWBlock = 200;
        nMaturity = 10;
        nSwiftnodeCountDrift = 4;
        nModifierUpdateBlock = 1;
        nMaxMoneyOut = 5000000000 * COIN; // 5B

        genesis.nTime = 1540687444;
        genesis.nNonce = 22026442;

        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x000003f64020a3817b950ad5910917642faff02e3d5ec7cca9262db1bbb63038"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("testnetseed.swiftcash.cc", "testnetseed.swiftcash.cc"));
        vSeeds.push_back(CDNSSeedData("testnetseed.swiftcash.space", "testnetseed.swiftcash.space"));


        // Testnet SwiftCash addresses start with 'T'
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 65);
        // Testnet SwiftCash script addresses start with '5'
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 11);
        // Testnet private keys start with 'U'
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 188);
        // Testnet SwiftCash BIP32 pubkeys start with 'tpub' (Bitcoin defaults)
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x87)(0xCF).convert_to_container<std::vector<unsigned char> >();
        // Testnet SwiftCash BIP32 prvkeys start with 'tprv' (Bitcoin defaults)
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x83)(0x94).convert_to_container<std::vector<unsigned char> >();
        // Testnet swiftcash BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "02c78ca70bcaea5468843854bebae65123b0e8ad99b0cbda98504160b71179d42b";
        strSwiftnodePoolDummyAddress = "THSwiJRv9UBw5pHVFxvzji5odtySjgyskh";
        nBudget_Fee_Confirmations = 3; // Number of confirmations for the finalization fee. We have to make this very short
                                       // here because we only have a 8 block finalization window on testnet
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        strNetworkID = "regtest";
        pchMessageStart[0] = 0x11;
        pchMessageStart[1] = 0xf2;
        pchMessageStart[2] = 0x43;
        pchMessageStart[3] = 0xff;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 40 * 60; // SwiftCash: 40 minutes
        nTargetSpacing = 1 * 60;  // SwiftCash: 1 minute
        nRetargetInterval = 1; // SwiftCash: each block
        bnProofOfWorkLimit = ~uint256(0) >> 1;

        genesis.nTime = 1540687443;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 21689207;

        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 48544;
        assert(hashGenesisBlock == uint256("0x00000928717cf50aacdb893a35686a88d33f912f60ff349ca90be0979301ce6e"));

        vFixedSeeds.clear(); //! Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Regtest mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 51488;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
