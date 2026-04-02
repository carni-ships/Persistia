// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/DoryVerifier11.sol";

contract DoryVerifierTest is Test {
    Verifier verifier;

    function setUp() public {
        verifier = new Verifier();
    }

    function test_verifyProof_realProof() public view {
        uint256[8] memory proof;
        proof[0] = 0x2143443eb98cfdfb3ec00629938b66b6c2adc3f1c7ba3a0f4ab90edfae053ff0;
        proof[1] = 0x141651891f7a49f391172e417ca4c18ff6f7ee6cfbdf0dd7f7d144b4ab5b0116;
        proof[2] = 0x1a6824445ecd4a9e67052d936b8ccea4d4feefe693c4462f6058630d637e1678;
        proof[3] = 0x02ffd793e4d69f5aa8c92edbde13e6f54cfaeeb4239c2b0fdc1d0de86b667fec;
        proof[4] = 0x2d1da2735311e4ec120f3a802a70ef12c133c4d3bfe89f5e6eca846c72e03e64;
        proof[5] = 0x2c34bcb4502e0e489f557802275bbcca7c4f26fc0b1c4c48011628aeec06f6e9;
        proof[6] = 0x2afb307a6469e75b4b89d7c49aba61c53d40a3e2b04c24cc430e09fd34e5b019;
        proof[7] = 0x0ce6bc5ce7a8e6a845de2987c6e61247ef2feb4e2ac2b942de36e392d8f5a8c9;

        uint256[2] memory commitments;
        commitments[0] = 0x131199b6be99ea611f9f8d97c51c4da4ab77d00ffc92747c47699bd3bc8188f1;
        commitments[1] = 0x23cb12e520c5131f61a6c79117abfdcb557364258529df9069137951eeeb5be3;

        uint256[2] memory commitmentPok;
        commitmentPok[0] = 0x1cbd78b57d9b2bce5a0fa0e1e85c8445cae63d8eee12a350111771f4c060f457;
        commitmentPok[1] = 0x0305ab6eb4cc7f5089d76c690a52434bdc322d09e7eb8106ce4f7a52b4d5d1a9;

        uint256[1] memory input;
        input[0] = 0x0de5aa35a3911ce0e1a0455950f923e332939267fb28e16b8fed281cd458936b;

        verifier.verifyProof(proof, commitments, commitmentPok, input);
    }

    function test_verifyProof_wrongInput_reverts() public {
        uint256[8] memory proof;
        proof[0] = 0x2143443eb98cfdfb3ec00629938b66b6c2adc3f1c7ba3a0f4ab90edfae053ff0;
        proof[1] = 0x141651891f7a49f391172e417ca4c18ff6f7ee6cfbdf0dd7f7d144b4ab5b0116;
        proof[2] = 0x1a6824445ecd4a9e67052d936b8ccea4d4feefe693c4462f6058630d637e1678;
        proof[3] = 0x02ffd793e4d69f5aa8c92edbde13e6f54cfaeeb4239c2b0fdc1d0de86b667fec;
        proof[4] = 0x2d1da2735311e4ec120f3a802a70ef12c133c4d3bfe89f5e6eca846c72e03e64;
        proof[5] = 0x2c34bcb4502e0e489f557802275bbcca7c4f26fc0b1c4c48011628aeec06f6e9;
        proof[6] = 0x2afb307a6469e75b4b89d7c49aba61c53d40a3e2b04c24cc430e09fd34e5b019;
        proof[7] = 0x0ce6bc5ce7a8e6a845de2987c6e61247ef2feb4e2ac2b942de36e392d8f5a8c9;

        uint256[2] memory commitments;
        commitments[0] = 0x131199b6be99ea611f9f8d97c51c4da4ab77d00ffc92747c47699bd3bc8188f1;
        commitments[1] = 0x23cb12e520c5131f61a6c79117abfdcb557364258529df9069137951eeeb5be3;

        uint256[2] memory commitmentPok;
        commitmentPok[0] = 0x1cbd78b57d9b2bce5a0fa0e1e85c8445cae63d8eee12a350111771f4c060f457;
        commitmentPok[1] = 0x0305ab6eb4cc7f5089d76c690a52434bdc322d09e7eb8106ce4f7a52b4d5d1a9;

        uint256[1] memory input;
        input[0] = 0x0de5aa35a3911ce0e1a0455950f923e332939267fb28e16b8fed281cd458936b + 1;

        vm.expectRevert();
        verifier.verifyProof(proof, commitments, commitmentPok, input);
    }

    function test_verifyProof_gasUsage() public {
        uint256[8] memory proof;
        proof[0] = 0x2143443eb98cfdfb3ec00629938b66b6c2adc3f1c7ba3a0f4ab90edfae053ff0;
        proof[1] = 0x141651891f7a49f391172e417ca4c18ff6f7ee6cfbdf0dd7f7d144b4ab5b0116;
        proof[2] = 0x1a6824445ecd4a9e67052d936b8ccea4d4feefe693c4462f6058630d637e1678;
        proof[3] = 0x02ffd793e4d69f5aa8c92edbde13e6f54cfaeeb4239c2b0fdc1d0de86b667fec;
        proof[4] = 0x2d1da2735311e4ec120f3a802a70ef12c133c4d3bfe89f5e6eca846c72e03e64;
        proof[5] = 0x2c34bcb4502e0e489f557802275bbcca7c4f26fc0b1c4c48011628aeec06f6e9;
        proof[6] = 0x2afb307a6469e75b4b89d7c49aba61c53d40a3e2b04c24cc430e09fd34e5b019;
        proof[7] = 0x0ce6bc5ce7a8e6a845de2987c6e61247ef2feb4e2ac2b942de36e392d8f5a8c9;

        uint256[2] memory commitments;
        commitments[0] = 0x131199b6be99ea611f9f8d97c51c4da4ab77d00ffc92747c47699bd3bc8188f1;
        commitments[1] = 0x23cb12e520c5131f61a6c79117abfdcb557364258529df9069137951eeeb5be3;

        uint256[2] memory commitmentPok;
        commitmentPok[0] = 0x1cbd78b57d9b2bce5a0fa0e1e85c8445cae63d8eee12a350111771f4c060f457;
        commitmentPok[1] = 0x0305ab6eb4cc7f5089d76c690a52434bdc322d09e7eb8106ce4f7a52b4d5d1a9;

        uint256[1] memory input;
        input[0] = 0x0de5aa35a3911ce0e1a0455950f923e332939267fb28e16b8fed281cd458936b;

        uint256 gasBefore = gasleft();
        verifier.verifyProof(proof, commitments, commitmentPok, input);
        uint256 gasUsed = gasBefore - gasleft();
        emit log_named_uint("Gas used for verifyProof", gasUsed);
    }
}
