// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/merkle.h"

#include "uint256.h"
#include "arith_uint256.h"

#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

// For equihash_parameters_acceptable.
#include "crypto/equihash.h"
#include "net.h"
#include "validation.h"
#define equihash_parameters_acceptable(N, K) \
    ((CBlockHeader::HEADER_SIZE + equihash_solution_size(N, K))*MAX_HEADERS_RESULTS < \
     MAX_PROTOCOL_MESSAGE_LENGTH-1000)

#include "base58.h"
#include <assert.h>
#include <boost/assign/list_of.hpp>

#include "chainparamsseeds.h"

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = ArithToUint256(arith_uint256(nNonce));
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.nHeight  = 0;
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "theguardian 09/SEPT/17 world is at its most dangerous point in a generation";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

const arith_uint256 maxUint = UintToArith256(uint256S("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));


class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256S("0x00000000419d2350e7f0d83851a25d9e73d5a2b92bdfbca45c1d65818a065043");
        consensus.BIP65Height = 30000; // ?
        consensus.BIP66Height = 30000; // ?
        consensus.BTGHeight = 26900; // Around 10/25/2017 12:00 UTC
        consensus.BTGPremineWindow = 8000;
        consensus.BTGPremineEnforceWhitelist = true;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitStart = uint256S("0000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitLegacy = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        
        //based on https://github.com/BTCGPU/BTCGPU/issues/78
        consensus.nPowAveragingWindow = 30;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32;
        consensus.nPowMaxAdjustUp = 16;
        
        consensus.nPowTargetTimespanLegacy = 14 * 24 * 60 * 60;; // 10 minutes
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespanLegacy / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000a7978cb4845455e14ab03555af5dd0f9d2066476430a240a240bc4c9"); //genesis for now 

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000000002930acd23c2518db69fec6ee17d614abf8f02365556110a388f"); //Last checkpoint for now //477890 (btg height)

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xf9;
        pchMessageStart[1] = 0xbe;
        pchMessageStart[2] = 0xb4;
        pchMessageStart[3] = 0xd9;
        nDefaultPort = 8319; // different port than Bitcoin
        nPruneAfterHeight = 100000;
        const size_t N = 200, K = 9;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(1504946630, 1143922723, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash(consensus);
        assert(consensus.hashGenesisBlock == uint256S("0x00000000a7978cb4845455e14ab03555af5dd0f9d2066476430a240a240bc4c9"));
        assert(genesis.hashMerkleRoot == uint256S("0xab389382081431342fdd6a946fa28faf6e1846f8cfc92fbff3d3c1df11d46874"));
		
        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top

        vSeeds.emplace_back("dnsseed.flurbo.xyz", true);
        vSeeds.emplace_back("dnsseed.boxy.online", true);
        vSeeds.emplace_back("dnsseed.boxycoin.org", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,35);  // prefix: G
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,95);  // prefix: A
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,48);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = (CCheckpointData) {
            {
				{ 0, uint256S("0x00000000a7978cb4845455e14ab03555af5dd0f9d2066476430a240a240bc4c9")},
				{ 1, uint256S("0x00000000419d2350e7f0d83851a25d9e73d5a2b92bdfbca45c1d65818a065043")}, //added test.
				{ 3, uint256S("0x00000000da524545fd1947fa1c577984f823a9a4a1cba3752b47383621056784")},
				{ 11111, uint256S("0x0000000000f36b7e56f02c45fb7f34b0994d34657bce54e9d7e7f80982fe2fbe")},
				{ 22222, uint256S("0x00000000000004f72b4d43aa2322332d27b030005bcc638ad433a1ca43ab7caa")},
				{ 24583, uint256S("0x00000000000002930acd23c2518db69fec6ee17d614abf8f02365556110a388f")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 000000000000000000d97e53664d17967bd4ee50b23abb92e54a34eb222d15ae (height 478913).
            1508144393, // * UNIX timestamp of last known number of transactions
            24891,  // * total number of transactions between genesis and that timestamp
                        //   (the tx=... number in the SetBestChain debug.log lines)
            0.0         // * estimated number of transactions per second after that timestamp
        };

        vPreminePubkeys = {
            { "02DAEF7919524D4DD04FA40FA6027BF7D9C2C3BCC06A8CFAE4BB09D2418B9BB232", "0340908883CD66BD58DD701B91BB7658620922D3968F40ADFD8F9FDF53579A2501", "02F6A1EF8EAF1C38DE5CB4B45E46159FBB32822D840A3416D8891A5EA9E024BE9E", "02019A537CA923E6F8EC1FC5A5ABF755DBB9C113A27FF3790FA1A319C6A0380171", "037D0698372FC9EEC5067A43EDBD7F0311BACA2E54C5ADF4478FC02E617AA32D50", "02bb4feeb207779054aacb49b61d325f46e0b98afb301a66dc32ca3e7484f419ef" },
            { "03349091B5A9AF9DFBB3C40D3E6B278A2FEF198D4F2159A714241F9E8BE275DBDB", "0340484CAEC65725F3B5116DF83B34EECA5641964A832F6A0F314536FE992B1F0F", "0326CD7D38FF2BAAC7EA917219B1CA431B106350DDFAAD2A874AAAFB450C3AFEE8", "03A8302CC65AF43D04E647E74687F7F6589EAEA78A05A10C20AA05A705A3075E6F", "032CA8B9BB4F1143F67CB203CAEF83E4B2706B307B9960B8B975F6179DF2A4B218", "031f4d880c835238b97625d20579940e965a833c30fb8f643bd5e6a43ef37e0ee7" },
            { "032066FB2CEBE8F285310B47E44A4E9FA35C17B48BE1B9D15BD74A7530290A87A1", "0228BAFC555A3905A09A0B8629790508524402F8828254F3D3BBC87F374A237473", "02C9BC409D7F7F5D3EAA27314B4221AF9AED3AF8A590442A0E6B5D5ED8846CE81E", "027F4CBB3DB2749D172CD80DD9034B404D2F99472DE3B1DA971D014FAD7562C189", "02fd5c856002b77384599ea9cd6ceae515223809e6f1b63d45be5456b409d2be8e", "02bf748f7e7291e9061f32bc72ea52a325154dadddb98348307838565fc8855f4c" },
            { "02ED1BDD686E7E2ED8DB2B187A2D1D3AD9DECAC5AF5649341C944E6B9EBD4BAB22", "03E10D61CB6F1072A7E8C5DD90543913C352FEA16F05EA9A0D6198C742A6573510", "037228F1E1A2D24FB078CE93009F1CC8D9DC30484170F675094F569C8D57DBA8E4", "03E1D3A96186F37E90D898D394A5D1A5FD823CC6C4EE2EB96BAB610B02227C4080", "032c8735d320b6219cb398999345fea9e6b234e5f7d9f96c6a2758658d261acd6d", "029860998228d746ec5ccdc47b451b3143c05f9e26b7b1a491d64429dcac3feb0e" },
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 2;
        consensus.BIP34Hash = uint256S("0x00000838618907497013c581b670287add08a9292237fbff71559a6e3f9fd96b");
        consensus.BIP65Height = 2; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 2; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.BTGHeight = 15000;
        consensus.BTGPremineWindow = 50;
        consensus.BTGPremineEnforceWhitelist = false;
        consensus.powLimit = uint256S("0007ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitStart = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitLegacy = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

        //based on https://github.com/BTCGPU/BTCGPU/issues/78
        consensus.nPowAveragingWindow = 30;
        assert(maxUint/UintToArith256(consensus.powLimit) >= consensus.nPowAveragingWindow);
        consensus.nPowMaxAdjustDown = 32;
        consensus.nPowMaxAdjustUp = 16;
        
        consensus.nPowTargetTimespanLegacy = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespanLegacy / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000258baee7750addb491fa64387402da664e234ff77e7b8e3897aed4700cc");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000258baee7750addb491fa64387402da664e234ff77e7b8e3897aed4700cc"); //genesis now //1135275

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x09;
        pchMessageStart[2] = 0x11;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 18913;
        nPruneAfterHeight = 1000;
        const size_t N = 200, K = 9;  // Same as mainchain.
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(1504946610, 789571, 0x2000000f, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash(consensus);
        assert(consensus.hashGenesisBlock == uint256S("0x00000258baee7750addb491fa64387402da664e234ff77e7b8e3897aed4700cc"));
        assert(genesis.hashMerkleRoot == uint256S("0xab389382081431342fdd6a946fa28faf6e1846f8cfc92fbff3d3c1df11d46874"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
		
        vSeeds.emplace_back("test-dnsseed.flurbo.xyz", true);
        vSeeds.emplace_back("test-dnsseed.boxycoin.org", true);
        vSeeds.emplace_back("test-dnsseed.boxy.online", true);

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,128);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,239);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,196);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = (CCheckpointData) {
            {
                {0, uint256S("00000258baee7750addb491fa64387402da664e234ff77e7b8e3897aed4700cc")},
            }
        };

        chainTxData = ChainTxData{
            // Data as of block 00000000000001c200b9790dc637d3bb141fe77d155b966ed775b17e109f7c6c (height 1156179)
            1504946610,
            0,
            0.15
        };
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.BTGHeight = 3000;
        consensus.BTGPremineWindow = 10;
        consensus.BTGPremineEnforceWhitelist = false;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitStart = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimitLegacy = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        //based on https://github.com/BTCGPU/BTCGPU/issues/78
        consensus.nPowAveragingWindow = 30;
        consensus.nPowMaxAdjustDown = 16;
        consensus.nPowMaxAdjustUp = 32;
        consensus.nPowTargetTimespanLegacy = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 999999999999ULL;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 999999999999ULL;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");
        
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xb5;
        pchMessageStart[2] = 0xbf;
        pchMessageStart[3] = 0xda;

        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;
        const size_t N = 48, K = 5;
        BOOST_STATIC_ASSERT(equihash_parameters_acceptable(N, K));
        nEquihashN = N;
        nEquihashK = K;

        genesis = CreateGenesisBlock(1504946610, 1, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash(consensus);
        assert(consensus.hashGenesisBlock == uint256S("0x662ff57202a75a233279b933528ff0cc8203115efe8a66dab682bb41db0b82a0"));
        assert(genesis.hashMerkleRoot == uint256S("0xab389382081431342fdd6a946fa28faf6e1846f8cfc92fbff3d3c1df11d46874"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = (CCheckpointData) {
            {
                {0, uint256S("662ff57202a75a233279b933528ff0cc8203115efe8a66dab682bb41db0b82a0")},
				{1, uint256S("4d5e6a2ed178ee299f907e1e0bed78484c91a8bb38e082bd968224eb56494579")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,239);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,111);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};
    }
    
};

class BitcoinAddressChainParam : public CMainParams
{
public:
    BitcoinAddressChainParam()
    {
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
    }
};

static std::unique_ptr<CChainParams> globalChainParams;
static BitcoinAddressChainParam chainParamsForAddressConversion;

const CChainParams &Params()
{
    assert(globalChainParams);
    return *globalChainParams;
}

const CChainParams &BitcoinAddressFormatParams()
{
    return chainParamsForAddressConversion;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}


static CScript CltvMultiSigScript(const std::vector<std::string>& pubkeys, uint32_t lock_time) {
    assert(pubkeys.size() == 6);
    CScript redeem_script;
    if (lock_time > 0) {
        redeem_script << lock_time << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    }
    redeem_script << 4;
    for (const std::string& pubkey : pubkeys) {
        redeem_script << ToByteVector(ParseHex(pubkey));
    }
    redeem_script << 6 << OP_CHECKMULTISIG;
    return redeem_script;
}

bool CChainParams::IsPremineAddressScript(const CScript& scriptPubKey, uint32_t height) const {
    static const int LOCK_TIME = 3 * 365 * 24 * 3600;  // 3 years
    static const int LOCK_STAGES = 3 * 12;  // Every month for 3 years
    assert((uint32_t)consensus.BTGHeight <= height &&
           height < (uint32_t)(consensus.BTGHeight + consensus.BTGPremineWindow));
    int block = height - consensus.BTGHeight;
    int num_unlocked = consensus.BTGPremineWindow * 40 / 100;  // 40% unlocked.
    int num_locked = consensus.BTGPremineWindow - num_unlocked;  // 60% time-locked.
    int stage_lock_time = LOCK_TIME / LOCK_STAGES / consensus.nPowTargetSpacing;
    int stage_block_height = num_locked / LOCK_STAGES;
    const std::vector<std::string> pubkeys = vPreminePubkeys[block % vPreminePubkeys.size()];  // Round robin.
    CScript redeem_script;
    if (block < num_unlocked) {
        redeem_script = CltvMultiSigScript(pubkeys, 0);
    } else {
        int locked_block = block - num_unlocked;
        int stage = locked_block / stage_block_height;
        int lock_time = consensus.BTGHeight + stage_lock_time * (1 + stage);
        redeem_script = CltvMultiSigScript(pubkeys, lock_time);
    }
    CScript target_scriptPubkey = GetScriptForDestination(CScriptID(redeem_script));
    return scriptPubKey == target_scriptPubkey;
}
