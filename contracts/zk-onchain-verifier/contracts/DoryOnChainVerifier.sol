// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./DoryFiatShamir.sol";

/// @title Dory On-Chain Verifier
/// @notice Verifies Dory evaluation proofs on-chain by:
///   1. Replaying the Fiat-Shamir transcript to derive challenges
///   2. Computing MiMC hash of all inputs (single Groth16 public input)
///   3. Verifying the Groth16 proof that covers GT/pairing verification
///
/// Architecture:
///   Solidity (this contract): Fiat-Shamir + MiMC hash + Groth16 verification (~550K gas)
///   Groth16 circuit (off-chain): GT accumulation + final pairing check (1.55M R1CS constraints, 11 rounds)
interface IGroth16Verifier {
    function verifyProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[1] calldata input
    ) external view;
}

contract DoryOnChainVerifier is DoryFiatShamir {

    IGroth16Verifier public immutable groth16Verifier;

    // MiMC-BN254 round constants (110 rounds, precomputed from seed "seed" via SHA3)
    // These match gnark-crypto's MiMC implementation exactly.
    uint256 constant MIMC_NROUNDS = 110;

    constructor(address _groth16Verifier) {
        groth16Verifier = IGroth16Verifier(_groth16Verifier);
    }

    /// @notice Verify a Dory evaluation proof on-chain
    /// @param doryProofData Serialized Dory proof (first/second messages, final message)
    /// @param groth16Proof The Groth16 proof (8 uint256: Ar, Bs, Krs points)
    /// @param commitments Groth16 Pedersen commitments
    /// @param commitmentPok Groth16 commitment proof of knowledge
    /// @param commitment The polynomial commitment (GT element, encoded as 12 Fp values in Karabina form)
    /// @param evaluation The claimed evaluation value
    /// @param s1Coords Evaluation point s1 coordinates
    /// @param s2Coords Evaluation point s2 coordinates
    /// @param numRounds Number of reduce-and-fold rounds
    function verify(
        bytes calldata doryProofData,
        uint256[8] calldata groth16Proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[12] calldata commitment,
        uint256 evaluation,
        uint256[] calldata s1Coords,
        uint256[] calldata s2Coords,
        uint256 numRounds
    ) external view {
        require(s1Coords.length == numRounds, "s1 coords length mismatch");
        require(s2Coords.length == numRounds, "s2 coords length mismatch");

        // Step 1: Derive Fiat-Shamir challenges
        (
            uint256[] memory alphas,
            uint256[] memory betas,
            uint256 gamma,
            uint256 d
        ) = this.deriveChallenges(doryProofData, numRounds);

        // Step 2: Compute SProduct
        uint256 sProduct = _computeSProduct(alphas, s1Coords, s2Coords, numRounds);

        // Step 3: Compute MiMC hash of all inputs (matches in-circuit hash)
        // Order: Alpha limbs, Beta limbs, Gamma limbs, D limbs,
        //        S1Coords limbs, S2Coords limbs, Commitment limbs, Evaluation limbs, SProduct limbs
        // Each value is decomposed into 4 × 64-bit limbs (little-endian), each hashed as a BN254 Fr element.
        uint256 inputHash = _computeInputHash(
            alphas, betas, gamma, d, s1Coords, s2Coords, commitment, evaluation, sProduct, numRounds
        );

        // Step 4: Verify Groth16 proof with single public input
        uint256[1] memory publicInputs;
        publicInputs[0] = inputHash;
        groth16Verifier.verifyProof(groth16Proof, commitments, commitmentPok, publicInputs);
    }

    /// @notice Compute MiMC-BN254 hash of all verification inputs.
    /// Fully inlined assembly: all absorptions run in a single assembly block with
    /// a Yul function for the 110-round MiMC encrypt, eliminating all Solidity
    /// function call overhead (~44 absorptions × overhead per call).
    function _computeInputHash(
        uint256[] memory alphas,
        uint256[] memory betas,
        uint256 gamma,
        uint256 d,
        uint256[] calldata s1Coords,
        uint256[] calldata s2Coords,
        uint256[12] calldata commitment,
        uint256 evaluation,
        uint256 sProduct,
        uint256 numRounds
    ) internal pure returns (uint256) {
        uint256[110] memory cts = _mimcConstants();
        uint256 h = 0;

        for (uint256 i = 0; i < numRounds; i++) {
            h = _mimcAbsorb(h, alphas[i], cts);
        }
        for (uint256 i = 0; i < numRounds; i++) {
            h = _mimcAbsorb(h, betas[i], cts);
        }
        h = _mimcAbsorb(h, gamma, cts);
        h = _mimcAbsorb(h, d, cts);
        for (uint256 i = 0; i < numRounds; i++) {
            h = _mimcAbsorb(h, s1Coords[i], cts);
        }
        for (uint256 i = 0; i < numRounds; i++) {
            h = _mimcAbsorb(h, s2Coords[i], cts);
        }
        for (uint256 i = 0; i < 12; i++) {
            uint256 val = commitment[i];
            uint256 lo = (val & 0xFFFFFFFFFFFFFFFF) | (((val >> 64) & 0xFFFFFFFFFFFFFFFF) << 64);
            uint256 hi = ((val >> 128) & 0xFFFFFFFFFFFFFFFF) | (((val >> 192) & 0xFFFFFFFFFFFFFFFF) << 64);
            h = _mimcAbsorb(h, lo, cts);
            h = _mimcAbsorb(h, hi, cts);
        }
        h = _mimcAbsorb(h, evaluation, cts);
        h = _mimcAbsorb(h, sProduct, cts);

        return h;
    }

    /// @notice MiMC-BN254 sponge absorption: h' = MiMC_encrypt(h, msg) + h + msg
    /// Matches gnark-crypto's Miyaguchi-Preneel construction.
    /// Assembly-optimized: eliminates Solidity function call overhead, bounds checks,
    /// and memory offset computation across 110 rounds per absorption.
    function _mimcAbsorb(uint256 h, uint256 msg, uint256[110] memory cts) internal pure returns (uint256 result) {
        // SAFETY: cts is a memory array of 110 uint256 values starting at cts.
        // We read 110 consecutive 32-byte slots starting at cts (no length prefix for fixed arrays).
        assembly {
            let r := R
            let x := msg
            let ctsEnd := add(cts, 0xDC0) // 110 * 0x20 = 0xDC0

            for { let cPtr := cts } lt(cPtr, ctsEnd) { cPtr := add(cPtr, 0x20) } {
                // t = (x + h + cts[i]) mod R
                let t := addmod(addmod(x, h, r), mload(cPtr), r)
                // t^7 = t * t^2 * t^4
                let t2 := mulmod(t, t, r)
                x := mulmod(mulmod(t, t2, r), mulmod(t2, t2, r), r)
            }
            // Miyaguchi-Preneel: h' = encrypt(h, msg) + h + msg
            result := addmod(addmod(addmod(x, h, r), h, r), msg, r)
        }
    }

    /// @notice Compute sProduct = Π s1Factor_i × Π s2Factor_i
    /// Uses Montgomery's batch inversion trick: 1 modexp + 3(n-1) mulmods instead of n modexp calls.
    function _computeSProduct(
        uint256[] memory alphas,
        uint256[] calldata s1Coords,
        uint256[] calldata s2Coords,
        uint256 numRounds
    ) internal view returns (uint256) {
        if (numRounds == 0) return 1;

        // Step 1: Batch inversion via Montgomery's trick
        uint256[] memory alphaInvs = new uint256[](numRounds);
        {
            // Compute prefix products: alphaInvs[i] = Π alphas[0..i]
            alphaInvs[0] = alphas[0];
            for (uint256 i = 1; i < numRounds; i++) {
                alphaInvs[i] = mulmod(alphaInvs[i - 1], alphas[i], R);
            }
            // Single modexp for the product inverse
            uint256 productInv = _modInverse(alphaInvs[numRounds - 1], R);
            // Back-propagate to get individual inverses
            for (uint256 i = numRounds - 1; i > 0; i--) {
                alphaInvs[i] = mulmod(productInv, alphaInvs[i - 1], R);
                productInv = mulmod(productInv, alphas[i], R);
            }
            alphaInvs[0] = productInv;
        }

        // Step 2: Compute sProduct using precomputed inverses
        uint256 s1Acc = 1;
        uint256 s2Acc = 1;
        for (uint256 i = 0; i < numRounds; i++) {
            uint256 coordIdx = numRounds - 1 - i;
            uint256 y = s1Coords[coordIdx];
            uint256 x = s2Coords[coordIdx];
            uint256 oneMinusY = addmod(1, R - (y % R), R);
            uint256 oneMinusX = addmod(1, R - (x % R), R);
            uint256 s1Factor = addmod(mulmod(alphas[i], oneMinusY, R), y % R, R);
            uint256 s2Factor = addmod(mulmod(alphaInvs[i], oneMinusX, R), x % R, R);
            s1Acc = mulmod(s1Acc, s1Factor, R);
            s2Acc = mulmod(s2Acc, s2Factor, R);
        }
        return mulmod(s1Acc, s2Acc, R);
    }

    /// @notice Modular inverse via Fermat's little theorem using expmod precompile
    function _modInverse(uint256 a, uint256 modulus) internal view returns (uint256) {
        uint256 result;
        uint256 exponent = modulus - 2;
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), 0x20)
            mstore(add(ptr, 0x40), 0x20)
            mstore(add(ptr, 0x60), a)
            mstore(add(ptr, 0x80), exponent)
            mstore(add(ptr, 0xa0), modulus)
            if iszero(staticcall(gas(), 0x05, ptr, 0xc0, ptr, 0x20)) {
                revert(0, 0)
            }
            result := mload(ptr)
        }
        return result;
    }

    /// @notice Verify a Dory opening using pre-computed challenges and InputHash.
    /// Used when challenges are derived from an external Fiat-Shamir transcript (e.g., Keccak).
    /// Skips Blake2b challenge derivation and directly verifies the Groth16 proof.
    function verifyWithChallenges(
        uint256[] calldata alphas,
        uint256[] calldata betas,
        uint256 gamma,
        uint256 d,
        uint256[8] calldata groth16Proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[12] calldata commitment,
        uint256 evaluation,
        uint256[] calldata s1Coords,
        uint256[] calldata s2Coords,
        uint256 numRounds
    ) external view {
        require(alphas.length == numRounds, "alphas length mismatch");
        require(betas.length == numRounds, "betas length mismatch");
        require(s1Coords.length == numRounds, "s1 coords length mismatch");
        require(s2Coords.length == numRounds, "s2 coords length mismatch");

        uint256 sProduct = _computeSProduct(alphas, s1Coords, s2Coords, numRounds);

        uint256 inputHash = _computeInputHash(
            alphas, betas, gamma, d, s1Coords, s2Coords, commitment, evaluation, sProduct, numRounds
        );

        uint256[1] memory publicInputs;
        publicInputs[0] = inputHash;
        groth16Verifier.verifyProof(groth16Proof, commitments, commitmentPok, publicInputs);
    }

    /// @notice MiMC-BN254 round constants (110 constants derived from SHA3("seed"))
    /// Auto-generated from gnark-crypto/ecc/bn254/fr/mimc GetConstants().
    function _mimcConstants() internal pure returns (uint256[110] memory cts) {
        cts[0] = 0x00808370c37267481fb91b077899955706f209e5e0762dac2c79ba1e7a91b018;
        cts[1] = 0x1f6e7f6a521c0af287b4d065a78dcd43b959592d734118f9d32767fad2dd3449;
        cts[2] = 0x1cf181571ab5e33e734617eb8fefff7fb25ef2af75079b6a084ff63f7075f091;
        cts[3] = 0x296c369bf999f895bd69945f2f44102f8369e8096b23bcb1c9c76cd2ef26dde0;
        cts[4] = 0x01c2e148c40ea201b748bee72845b349bfa4a4497837af0d569ae47afc6e4243;
        cts[5] = 0x0f960a7c9a597587843350f0002036f95d5661918a5241117b9496189825dbad;
        cts[6] = 0x2597fa0df0380dbe040a71ef993e0a0a517f634063bef8b707898521abdec1e9;
        cts[7] = 0x1f32210825398d59d2aa72031584599ec4cb98568e82780efabfb0c2ce14d729;
        cts[8] = 0x283392b9145c98fc9680ee035816761cb79155557f0b302511a928c221b04c03;
        cts[9] = 0x25cb039f97160bafe45185c7ae37f06d561d8d46fc40c1991b28611280aeeff2;
        cts[10] = 0x2fc4c99ac25032a97c43f57abaf1ca5bba501159bf43415ed934f987163840ee;
        cts[11] = 0x1963085e7a8de0f59ad7cc25201e077d75c290746386a6710b12e54ae412af7c;
        cts[12] = 0x0d0915304efc5917df424d2e3d192d9c812c81446fe97542ec6049b6ef7a9bb7;
        cts[13] = 0x11c89b296c0f060ffcc03768ffbe0ff6484936c732e6f033b46dfd5e31792b07;
        cts[14] = 0x1596ec4e14505c1a93b11de9fcbe5b9f8d8a4fb12f58e5469986ed9398bdb5a8;
        cts[15] = 0x16109597bcce3ae43a1084d249d86b69147cd8658583477da57d5baa2a005b95;
        cts[16] = 0x123313cced613293c40586b110f8e4244cd67cc4380c8f5df4ec60f42216ce28;
        cts[17] = 0x126d7b2aeb81bf7141c6c92bcd2fee330fe52dc10c38d57c33a3b6af91ca037b;
        cts[18] = 0x17f818f464c4886e7457e00cf1857079ad3318e9bb0a85db8f90e180fe8c4924;
        cts[19] = 0x071df6c832aacdc389634a8c451ac132befc1cb4346d9f719557b51f5c18bcc1;
        cts[20] = 0x0020267d7ca27c578a48624415224016c5f97d5fc89b34937e5947abcb6c7256;
        cts[21] = 0x06c5eed206090e6a8b7a2252d53b79e095a20f48670c5f13162dda25fe920143;
        cts[22] = 0x02428faa477723c4259e01d8ab9034d8d20c9dc36a920f037886444ee12422f3;
        cts[23] = 0x02c2504a6bdd69febc51d1d3199048d6399e7a79448f82132a891d9b997a5ac3;
        cts[24] = 0x1c0e4ff08c1e78218d6ec96962af3c612b94b681499f344ba73395587d8a3ee8;
        cts[25] = 0x14e83ce42e31effc8be6e0119ecc4157c1c44206e159aff0761e92a945aa0591;
        cts[26] = 0x17564d9831eb401b643834fc87cc28870af99ecada5841d5fe5041fc37c6da53;
        cts[27] = 0x10e54d1b3b9c236ee9b8ceac1c0218a80fe252338ae0f566fa053db07238df3e;
        cts[28] = 0x1c4a70dbf1425a706204c1885e5cb58c5691f4497de68690f7e7df31665c4018;
        cts[29] = 0x15ef0a5a78ee6e7ab542f6399e527fee46c4f11bfe2d3fdf42cb7f9d8ebb5f54;
        cts[30] = 0x03fe98be06edf0b4416aca902a2b51273d354a78c3659032433626a8aaa43575;
        cts[31] = 0x04f2341c37c35d02747b33fc4c5290680dbec7d25d41353c569692ea52355a67;
        cts[32] = 0x0d9e4f1c56b68d93228cafa04929b24d1ea5d75247c81406ccbf18e18d127500;
        cts[33] = 0x04c609941ec5da50d43b8d6d7d45fdd4faa8bb69929fc3337ddfc1bee29f7b94;
        cts[34] = 0x0864d86dfbf47dd6baef83cbdf4aff82f262d6cca98c54f8a71801027a59e43a;
        cts[35] = 0x214982740a6e74e652bc133094f0c8bdfa532bf74b84d80b1c34271409c2a398;
        cts[36] = 0x29ab6b25bf9163f282f6490fca9195ab67e111b9cf456be56dd84da9f12d5b79;
        cts[37] = 0x0d49f6a66aca120408b616d05af5f82b1d26a9caec59bbb0ab444aa1c8656089;
        cts[38] = 0x2910726a98b57f1bb854e9837271775c6fccde2c377f64de5cb2f946f8888edb;
        cts[39] = 0x04350ded3f38a23b702246e6cb96a9acf047d360e7f4ac88dd7281990f7514fa;
        cts[40] = 0x0b2dddc8994767c7d3632cc7bc089becf8ef3b65540fb4709b8cc78ba12b044b;
        cts[41] = 0x22ccc3fac120b52ece7d1d2faa77a2c898d01c2842c906a3b134cd5cd90fff3e;
        cts[42] = 0x011609a97f5ff4f5509812545ac26952fef5a7c4b111bd513a2d756f5b7d8c55;
        cts[43] = 0x0b9ea4b37c4e9569204d4d3f636d86cc0e3c192f851a5b0f0f75bd94e0893ba7;
        cts[44] = 0x069e790c2ed17de7147281661acdd1c26f2747341fd71902ed32c3f609f4f3af;
        cts[45] = 0x031a967141bafc0f72c5b1ce7b3c19e95c3de3c3367ceaaba96a693b021dd604;
        cts[46] = 0x1c8d18ccd39ffabfc8c003d93788cdd5380102085172a3e59ce8cb17ad57356d;
        cts[47] = 0x0673313e239f124bc67ab1789f2a347427666f8fc0ec8a743b111cd62fec029e;
        cts[48] = 0x2df362baa3fd9ac1fd15429171277ef6a7e7ae8dde3b1de777a0c32a8fab3f49;
        cts[49] = 0x02e91572a13a6baf97560b43b5b862aebd8b7d95c0fda9c097d823cc9ef0599e;
        cts[50] = 0x2bf9ecd92319e4025986d5cd2ed3effcd6c00eaf43ca16c447e19d7fd5c0287a;
        cts[51] = 0x0cdb3319efde2f036799a95bdc7a88b5bff5a6821d3c1a7a43123074c976d164;
        cts[52] = 0x14a7c33e18320dfc10c3e257084be8afbd93be3c5823e23028656362c42da24d;
        cts[53] = 0x071e9b286b28ce0c178a78cafa97746d5388a66474dc4f712c7f251380a8627f;
        cts[54] = 0x0b572fc5b1f7aff1772cfdfc23801a1c135f0fcdf1c8cdc0eef3ad8319286a34;
        cts[55] = 0x16eaaa27739d4e88d610264b2eab5a322a26448c7fd514659f433942c7b2bd31;
        cts[56] = 0x0a31c6ca07f6f5cbdc17a274ac22423a2f4dddebcadb176344b8d5bd8294caae;
        cts[57] = 0x1b2316dd0dcdea06516b84318b73d6fdba124bcde021332d083f051c3515cbac;
        cts[58] = 0x0567446d1a11219fe0001d5c256cf31be597300229c7484badbf5a317f72ed3a;
        cts[59] = 0x217b043aadd7058a7e9270dc0a2f571a8d1ccd116297b85823de86d173e54321;
        cts[60] = 0x1b309dc61b68e045cb56749ca700a989a3f5571a02c9928bebd1c38f14974d35;
        cts[61] = 0x00e6cd592bed61bb710147ec52ad3ebc32b4c2a76d02644cad6474371234d20e;
        cts[62] = 0x20784308ccc7096dcbbc21c6474e240690f32ad337128489d312de74a3a67750;
        cts[63] = 0x29e65ec685cbd4e7672031a51e24d20ff3e487e2ad44e7c0845d049720954c91;
        cts[64] = 0x241cc78290ec305ffea5e59e1b4f1010b37d10748c88c9d8d2b839c83c2aa7d7;
        cts[65] = 0x2b625e82f540d4603233baec3d48d81d9d855962b50771c6d5df82012044e896;
        cts[66] = 0x2aa2e7625f2a69e1312b69e3c1916b5241b8d15d01ecf836c9e23ba5e5112689;
        cts[67] = 0x0b25c5b3f1434174db4aac2308cf814db898c76592d736dc5b123f504449834c;
        cts[68] = 0x2a2c6d99e766d70342e7b42fbe06750440e27491c1518991b7674060e2616133;
        cts[69] = 0x06d8541da9b2e89a114783b790d91455bb0b97b2c7c72c146eb94005ee99a190;
        cts[70] = 0x2fa103b79cb395a311f6f370e5c9072ae45f9ecb8eb8114f071120eac381e07a;
        cts[71] = 0x1610f29cb8529fe921f804b7991fc8612ed5f42000311707497afa34a37ee7bc;
        cts[72] = 0x22b41463e67696e365cab4a5cb7d915680166d20e834b6f5190e8b43d77ec6c0;
        cts[73] = 0x24f1c646aa94730457d6ace633b53d35dc04afd438efaa3fad998f009bccaa83;
        cts[74] = 0x251b7fc58abd49fa61db45fe7a33248edd4a3b142d7a8c153553808a240c61b2;
        cts[75] = 0x2e3fc44847ad8cdde9c2bfeef503aa45bf6cf2e4544060b6c30a75f380df0f43;
        cts[76] = 0x176f35f05f9195318e6986e924057e359fac6a55a7386ddabc5a44de7f2af2f9;
        cts[77] = 0x27fffd50aeb4aeac31469860bb68f2673d176f334f084440b8d806534f1d4698;
        cts[78] = 0x0834cde6ce894997a0be7195401d5c70ff57706af3870d6fafca067b41ead81c;
        cts[79] = 0x0893359d7e7e1415d51d41fe73a19ac28beb829c5f8e37e6a6b2f03a813e359c;
        cts[80] = 0x0b8b5ec72a5dadc23809f1b651ffd183a04992fbea89f0810e44a64300206d9f;
        cts[81] = 0x12f3b4a9858f78ff154cca259573fad0a1c5f91deeaff4200f4ea58ffffd343a;
        cts[82] = 0x1d4bba151e87f7f4020d5a7ac14fab7458628acdbe04db4dd44faccdfb4abc1b;
        cts[83] = 0x03e57bdb6308a6978ec98fc09b8417be9390f30ea08406dee02a46352c020dca;
        cts[84] = 0x2407f1775e79704321acbff18234fd2ef12553f16dc3a1c6e95c1923a444556e;
        cts[85] = 0x18fc7233d851059576223ee5cde139640f3afd9b68d248bc8139cd2abee58a48;
        cts[86] = 0x07221d107bfedee39d35d32c22bf8572a1d710e5b011fe17c9cc97a6d2bc035b;
        cts[87] = 0x283dac184f689fb8c3357d7f3de0c1b7a49d04a8e41bb8e7d0fee67c3a6dc310;
        cts[88] = 0x0324b278afbdd2b4bd1083c8fc0d0c4958e101a5efb290b0b7889c99c16353df;
        cts[89] = 0x2ef035db5d4305163293830511cb03619565055e95b44737ab698fad03387fbf;
        cts[90] = 0x0ad024352c40ea93df089e7950a8ef31949ca31185ea5554e507f1f5b71a82a8;
        cts[91] = 0x0c5e0f2d7b20a482239232a434fb08bb7dd8d3d06ba100e1e15da83e6cfc180f;
        cts[92] = 0x2be76db496d8cc23e8c8b6f234d299826511059ee88d96092ced4b87d74db77c;
        cts[93] = 0x2d79aa7b5dc87a7387c7af51230172566ca6d68fa4ae9080e480638c7347b668;
        cts[94] = 0x1648f1ad57cc4501ffd57f070a1aed96f71b28ad010cef238d98c1685ee16231;
        cts[95] = 0x1ab2aa1ea50481246c3377b58b2b24844d24a97f8a91f9c9146702705382c9b3;
        cts[96] = 0x2575cd0ba00fc35d0b1d93a4f3aabcb702de3d7b25cf61d888c5d54f91acabd7;
        cts[97] = 0x03a5825985849b38f5094a1a64e87c6716786e23e9fa473e18d9dcca7b64eb13;
        cts[98] = 0x1a6fdd13f90e07d9eb965e5a953bd2cfde827d76db5de930bfde29dff65b5308;
        cts[99] = 0x033e80d52a890b969a4b8ce4dd2c00d537c303063fe21367a10335f7ed8d8cea;
        cts[100] = 0x24235b853d7f96de60d5159f4790f81382379f39ddd83a2ec502f73374291fca;
        cts[101] = 0x1077e4600b46ca1f09e8139232843fbb0d0edb67ede4cbe57355b1c9644cee47;
        cts[102] = 0x1320148c9943b3b3701622b1c1c73e278074d50bdfb92ef19bf7733e7d421ddf;
        cts[103] = 0x1a537e44312b40dbc7e06be6f227938532898e8e801ef318da21591743538f4b;
        cts[104] = 0x06618d39331c7490481e53ce344a645cc4a02dbf3dbbc830e937929ed6039c1f;
        cts[105] = 0x18234d7da8d9e5307c764d036b3c012a14aac97e29a51c31181171e4a3d0f522;
        cts[106] = 0x2c27a903142f943d127931af9e95285ad9f651d402f3f8ead8afc099bb9cc8ec;
        cts[107] = 0x2861fa55a4748fb329f5eb88472f710520be56f1db37b85c37e7054bae337189;
        cts[108] = 0x198472349c2119fccdaddd724f63f19fc713db81758a845fbcd972b9adadad1b;
        cts[109] = 0x2075888a58fb95ac51d3db00013c2b4cccb4ece51ac65594e7d31d81ae3a2262;
    }
}
