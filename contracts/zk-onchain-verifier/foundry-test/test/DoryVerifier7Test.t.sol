// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/DoryVerifier7.sol";

contract DoryVerifier7Test is Test {
    DoryGroth16Verifier7 verifier;

    function setUp() public {
        verifier = new DoryGroth16Verifier7();
    }

    function test_verifyProof_joltExport() public view {
        uint256[8] memory proof;
        proof[0] = 0x219d442615a87c6a045bfa4960cfa0d76c15184734922ac962b018096f41edc9;
        proof[1] = 0x1fb01fb51459d7aff5024acfdccee5735a3cc4b6d880592aea705164b2648e23;
        proof[2] = 0x21509f6418f213c1830f0350ac09be9dc51f95a62d486f23ac231c3cfa5d56b3;
        proof[3] = 0x05cc7a5b6b22bce13b67a86ebe70eaaf08b4edcfe421e25631b5467ff34f77cb;
        proof[4] = 0x287a7c3b9865682e70fa18df5aad5b7e00f141bd773a5baf47f44c492946254a;
        proof[5] = 0x1839cfd497f69bf7717688cf42c0ce8cbe240a59fffeede62bcbee407de415d5;
        proof[6] = 0x19c9d39758c2a0c1c2868e20b8307a5ba71da1a242f6d82d1b2c674fb1edf1ec;
        proof[7] = 0x24a0e4d56696dc3bb76c8e94cb8fef331ba97a748b27a43b3b9887d13eeb3590;

        uint256[2] memory commitments;
        commitments[0] = 0x21624bf4e1ba468986bcaa30dff4a5589d19b543e22db2548a4c592a4e39e5fd;
        commitments[1] = 0x23c002047ba947921f08528dba7cda7e118e6cb5ea9853c677d3f5d230cadc8c;

        uint256[2] memory commitmentPok;
        commitmentPok[0] = 0x2faf2a927edf072f7e88f9c76c02913b23760cafe036df7da3c7890de8221783;
        commitmentPok[1] = 0x1dfbfbefd33892ff8006a966c5f25009a0c2a85a0d72bff65f990351f547174e;

        uint256[1] memory input;
        input[0] = 0x1d3ce1bfe4a6824f5a4796a1ce7de3cacc5be126b975d4da157c56a83db7fd37;

        verifier.verifyProof(proof, commitments, commitmentPok, input);
    }
}
