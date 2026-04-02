// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/DoryVerifier9.sol";

contract DoryVerifier9Test is Test {
    DoryGroth16Verifier9 verifier;

    function setUp() public {
        verifier = new DoryGroth16Verifier9();
    }

    function test_verifyProof_sha3Production() public view {
        uint256[8] memory proof;
        proof[0] = 0x0a2253821107f0127ccded23206b5be42d584acbd205cf600addbcee20c4441b;
        proof[1] = 0x0558c77335bd12c139c658df9ee4d6b04e12fadf9c3116f0bc38814e167c16ed;
        proof[2] = 0x25af35ebdb9621cdb2b03854e848c55a8a647353287d900badf79da8a87e8b09;
        proof[3] = 0x288c2f8bfa7e6561d61d84c57629f4b885d32dcc3cba8e2fa309a257aaca811b;
        proof[4] = 0x19c912d7a104925c6e58838900758f88e041ea3310a51eed6f5896585aaf1c96;
        proof[5] = 0x1a04e63d00e4ccbf9e43728b436c416d651faa5890e89f4fadf7a9a14992732c;
        proof[6] = 0x2e017cd87b7aaf81923cebfdc492120ef5e28f747a5cd711e4cc97547a285c03;
        proof[7] = 0x09169e387c7d0bdaf1ff2d3f14dde0608f07dd08b4ba959a49e8dd92f7e1250e;

        uint256[2] memory commitments;
        commitments[0] = 0x2f6602297176d44e52aa705bc6c2191cda2683d012fd4cc94ea048d490a54dd7;
        commitments[1] = 0x153c7d10c3e36aa747c1461d968b295601627bd7a7dd5132d13f9e81c9eaf8af;

        uint256[2] memory commitmentPok;
        commitmentPok[0] = 0x08fe18284d21c99c9f01b2711dda47fee045981f389a611ce035dcb2f0fafd50;
        commitmentPok[1] = 0x29d45ec49a46196f6b493eca00b08dc2ee5a5381dd8eff11261e584e972221db;

        uint256[1] memory input;
        input[0] = 0x202ddb38ad15448e0c56307298ba142d5c1d7fbfe483e48039649167fd291cd7;

        verifier.verifyProof(proof, commitments, commitmentPok, input);
    }
}
