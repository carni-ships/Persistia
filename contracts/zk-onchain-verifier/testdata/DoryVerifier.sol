
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/// @title Groth16 verifier template.
/// @author Remco Bloemen
/// @notice Supports verifying Groth16 proofs. Proofs can be in uncompressed
/// (256 bytes) and compressed (128 bytes) format. A view function is provided
/// to compress proofs.
/// @notice See <https://2π.com/23/bn254-compression> for further explanation.
contract Verifier {

    /// Some of the provided public input values are larger than the field modulus.
    /// @dev Public input elements are not automatically reduced, as this is can be
    /// a dangerous source of bugs.
    error PublicInputNotInField();

    /// The proof is invalid.
    /// @dev This can mean that provided Groth16 proof points are not on their
    /// curves, that pairing equation fails, or that the proof is not for the
    /// provided public input.
    error ProofInvalid();
    /// The commitment is invalid
    /// @dev This can mean that provided commitment points and/or proof of knowledge are not on their
    /// curves, that pairing equation fails, or that the commitment and/or proof of knowledge is not for the
    /// commitment key.
    error CommitmentInvalid();

    // Addresses of precompiles
    uint256 constant PRECOMPILE_MODEXP = 0x05;
    uint256 constant PRECOMPILE_ADD = 0x06;
    uint256 constant PRECOMPILE_MUL = 0x07;
    uint256 constant PRECOMPILE_VERIFY = 0x08;

    // Base field Fp order P and scalar field Fr order R.
    // For BN254 these are computed as follows:
    //     t = 4965661367192848881
    //     P = 36⋅t⁴ + 36⋅t³ + 24⋅t² + 6⋅t + 1
    //     R = 36⋅t⁴ + 36⋅t³ + 18⋅t² + 6⋅t + 1
    uint256 constant P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47;
    uint256 constant R = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001;

    // Extension field Fp2 = Fp[i] / (i² + 1)
    // Note: This is the complex extension field of Fp with i² = -1.
    //       Values in Fp2 are represented as a pair of Fp elements (a₀, a₁) as a₀ + a₁⋅i.
    // Note: The order of Fp2 elements is *opposite* that of the pairing contract, which
    //       expects Fp2 elements in order (a₁, a₀). This is also the order in which
    //       Fp2 elements are encoded in the public interface as this became convention.

    // Constants in Fp
    uint256 constant FRACTION_1_2_FP = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4;
    uint256 constant FRACTION_27_82_FP = 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5;
    uint256 constant FRACTION_3_82_FP = 0x2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e775;

    // Exponents for inversions and square roots mod P
    uint256 constant EXP_INVERSE_FP = 0x30644E72E131A029B85045B68181585D97816A916871CA8D3C208C16D87CFD45; // P - 2
    uint256 constant EXP_SQRT_FP = 0xC19139CB84C680A6E14116DA060561765E05AA45A1C72A34F082305B61F3F52; // (P + 1) / 4;

    // Groth16 alpha point in G1
    uint256 constant ALPHA_X = 12459645521824280671748604781675058950153379563482724823341423167858840843953;
    uint256 constant ALPHA_Y = 8715626063373044880087972874495759495763963128925285211915197249644553001958;

    // Groth16 beta point in G2 in powers of i
    uint256 constant BETA_NEG_X_0 = 3936134941746820044367301461523140323923449670687981924152777427913761342050;
    uint256 constant BETA_NEG_X_1 = 17370538612828467986274046976844644534505115456151302807317150742225871544935;
    uint256 constant BETA_NEG_Y_0 = 15795862628005727554965128392928351606155304541301085943960801305723192223150;
    uint256 constant BETA_NEG_Y_1 = 16551396378608867665526286567494649905990724636242410236544868142624262905608;

    // Groth16 gamma point in G2 in powers of i
    uint256 constant GAMMA_NEG_X_0 = 9754940514872263422724701429920614831953118322714135514404638420707642321499;
    uint256 constant GAMMA_NEG_X_1 = 13899010986576647098412771700721899537095820412437934327130638234687895894423;
    uint256 constant GAMMA_NEG_Y_0 = 4348240284405081809075488201775046383201456930278618685813201265564652588540;
    uint256 constant GAMMA_NEG_Y_1 = 4883961089748009797913880063171331266953629640997488385493116393646473989561;

    // Groth16 delta point in G2 in powers of i
    uint256 constant DELTA_NEG_X_0 = 11331127175424596857449110188803177667498838521169802538906823257829450678481;
    uint256 constant DELTA_NEG_X_1 = 18185596174967895786984698363107877743770801653345621094224111994929731293640;
    uint256 constant DELTA_NEG_Y_0 = 13051507169352440191807437987249889420243725794997401035775278200702929222872;
    uint256 constant DELTA_NEG_Y_1 = 21272895812420938264584955050333063051840916763019485638622139226191373114237;
    // Pedersen G point in G2 in powers of i
    uint256 constant PEDERSEN_G_X_0 = 1933155241404477926521451448202488207152596921446319639279082310728669428906;
    uint256 constant PEDERSEN_G_X_1 = 12109642280311161972919802014153367567185673234576466881354693471406267378056;
    uint256 constant PEDERSEN_G_Y_0 = 19945365725562217256322001283095725122844853088334134782548073286136839523091;
    uint256 constant PEDERSEN_G_Y_1 = 6533012849363087337147166290022447621141253024100794272306932431936992966775;

    // Pedersen GSigmaNeg point in G2 in powers of i
    uint256 constant PEDERSEN_GSIGMANEG_X_0 = 3268282885124946228379202567207247530577578552041942474648755778973884648444;
    uint256 constant PEDERSEN_GSIGMANEG_X_1 = 14737058632966505887980114187395432844095989454594482184575446093491500821547;
    uint256 constant PEDERSEN_GSIGMANEG_Y_0 = 5151662320767997940728622959805245639424407050353439277570750043725714694984;
    uint256 constant PEDERSEN_GSIGMANEG_Y_1 = 17779018891205465075852714693698264890259039974039479663383869516599598740295;

    // Constant and public input points
    uint256 constant CONSTANT_X = 4785546249093113874164896680038922924367078502156652486934920111938518216944;
    uint256 constant CONSTANT_Y = 10699348657006508769013737469554443175924647507993119770161128266789990678160;
    uint256 constant PUB_0_X = 18833768077015345574452468073418581357401968473980311253489053752385052049443;
    uint256 constant PUB_0_Y = 2047521220754747204934376881306238062393833144245150785217240494686206025491;
    uint256 constant PUB_1_X = 2626010292465455887147114756686735598385031628329072450610099614269348876387;
    uint256 constant PUB_1_Y = 7717601732192913675486530267697248070578318493793014452999502493111608150433;
    uint256 constant PUB_2_X = 14975621395921107862977413361448767863272952033182764237933586416494695763687;
    uint256 constant PUB_2_Y = 7525452875648798929546183259834608392828923945898923049057669386665086575555;
    uint256 constant PUB_3_X = 5705286094682004652968753422846068422876645077339650574620563052694429476245;
    uint256 constant PUB_3_Y = 20296044519813215922568538605029241828416081397689980538040227375072063908116;
    uint256 constant PUB_4_X = 988223289803718380224196564883628532519037472802067098047172217122273119650;
    uint256 constant PUB_4_Y = 8661191546858820713698451013814468221248399893015141034088536941329655189245;
    uint256 constant PUB_5_X = 12988379509488605813516409484287979496425881178202027170928917318022103454481;
    uint256 constant PUB_5_Y = 20545922250406875056159759141524327619359950410068105048422164334635084825482;
    uint256 constant PUB_6_X = 17350039261823820336675425666133933711622257288589095038218245107113693654145;
    uint256 constant PUB_6_Y = 5685043948228169091239931226540104645360446166812422610470755924582984805227;
    uint256 constant PUB_7_X = 491378563870386212495542024767819142442728406500036267770359862036122258232;
    uint256 constant PUB_7_Y = 2090734742802347214811491079686533932653215748747822366501022574904268234260;
    uint256 constant PUB_8_X = 19064630571497662205410769214843216095641750728545360770726941844006916786352;
    uint256 constant PUB_8_Y = 21868896074370992901919863412776363665885833617545074780245178677828927176052;
    uint256 constant PUB_9_X = 21867774457871391514143802583454969232251596249934252369563534620173779671100;
    uint256 constant PUB_9_Y = 8018149847017905644215214144182625603479868848881712398834960228484149841587;
    uint256 constant PUB_10_X = 3643519442258053024569461426394052710149507566410369036928270052313882934692;
    uint256 constant PUB_10_Y = 2228425982588692163787654784306555276661490965589718755214339326397867950130;
    uint256 constant PUB_11_X = 12079072502404567650335714596785282955098496930815285352921884855240756093815;
    uint256 constant PUB_11_Y = 8623564991057035620093691226515023329179946129615064563494469595557732151952;
    uint256 constant PUB_12_X = 11984586016903850094977080242765783186473766296042157829522439970820603234289;
    uint256 constant PUB_12_Y = 21145530629725759313147392791737657845233909116624341477768507872271807399858;
    uint256 constant PUB_13_X = 18345240635420481709137135530476424180983473430176463922340347271713716249018;
    uint256 constant PUB_13_Y = 18798535029071860741751482587878820540790671028594651666137813822286616891398;
    uint256 constant PUB_14_X = 10010943537520432465450080357446083368076645697988678540980873340851132907663;
    uint256 constant PUB_14_Y = 5941708933396064251137757915145847821099760143335677360408023841739391831788;
    uint256 constant PUB_15_X = 5324153907203698752142484175675270193811086837020956093004075778948763276609;
    uint256 constant PUB_15_Y = 3849149904461763417140831922483226757633517588157103352718024331158565309067;
    uint256 constant PUB_16_X = 0;
    uint256 constant PUB_16_Y = 0;
    uint256 constant PUB_17_X = 0;
    uint256 constant PUB_17_Y = 0;
    uint256 constant PUB_18_X = 0;
    uint256 constant PUB_18_Y = 0;
    uint256 constant PUB_19_X = 0;
    uint256 constant PUB_19_Y = 0;
    uint256 constant PUB_20_X = 0;
    uint256 constant PUB_20_Y = 0;
    uint256 constant PUB_21_X = 0;
    uint256 constant PUB_21_Y = 0;
    uint256 constant PUB_22_X = 0;
    uint256 constant PUB_22_Y = 0;
    uint256 constant PUB_23_X = 0;
    uint256 constant PUB_23_Y = 0;
    uint256 constant PUB_24_X = 0;
    uint256 constant PUB_24_Y = 0;
    uint256 constant PUB_25_X = 0;
    uint256 constant PUB_25_Y = 0;
    uint256 constant PUB_26_X = 0;
    uint256 constant PUB_26_Y = 0;
    uint256 constant PUB_27_X = 0;
    uint256 constant PUB_27_Y = 0;
    uint256 constant PUB_28_X = 0;
    uint256 constant PUB_28_Y = 0;
    uint256 constant PUB_29_X = 0;
    uint256 constant PUB_29_Y = 0;
    uint256 constant PUB_30_X = 0;
    uint256 constant PUB_30_Y = 0;
    uint256 constant PUB_31_X = 0;
    uint256 constant PUB_31_Y = 0;
    uint256 constant PUB_32_X = 6752162512652102715872804237665789566983154648164603367038559933570235339152;
    uint256 constant PUB_32_Y = 15497452412349921853822399830030034065735600592483673444081635952384168270866;
    uint256 constant PUB_33_X = 8770682613279247496096844914237272239756442700880623455078801695878599581815;
    uint256 constant PUB_33_Y = 14707538336895726740017476328947112457391583399565611632385059372440639719328;
    uint256 constant PUB_34_X = 9468824125768315469746571180476605358132837970720663526740221066017905538819;
    uint256 constant PUB_34_Y = 10322353805153458650350902624441378170927379230254593538445051316169171674341;
    uint256 constant PUB_35_X = 5908108466205433507395727519129884048228629998900074084235487735967794116353;
    uint256 constant PUB_35_Y = 14033038639819603680737593878315767838693036385713585301242125186740223960840;
    uint256 constant PUB_36_X = 16586033614771193241452263287420098280421119964365120344528397639967097710253;
    uint256 constant PUB_36_Y = 14591290713843847809388213488650699385004842945476373289246815492504728717885;
    uint256 constant PUB_37_X = 21235508435609923800652958946310570874918157704389264697172799952186687504604;
    uint256 constant PUB_37_Y = 19837276994211484057076530090946438577930638464912493186149948198664545112789;
    uint256 constant PUB_38_X = 21532451890416975995388783299913008208864454527637135684285289152929328722202;
    uint256 constant PUB_38_Y = 7122749136999206084427352109263143643536168808425530440128222280225635550318;
    uint256 constant PUB_39_X = 2292369190387410416076716400117906322052940264432122473909971885944956036748;
    uint256 constant PUB_39_Y = 15190760923960947958274551172122766003027664447277726932110312897661745129473;
    uint256 constant PUB_40_X = 17586585123930437683041919975684927567876790263153099859403596305252815746329;
    uint256 constant PUB_40_Y = 11166083305279781930127236808037687638943882570763657857658124813268910612597;
    uint256 constant PUB_41_X = 7864139853071972057374156720653306535713162642979429076076312431855820130828;
    uint256 constant PUB_41_Y = 14847824785779472176251686722231080664753604867128642281083428022331114670490;
    uint256 constant PUB_42_X = 9024467623523627013594175011546601049217778490185920979645862866836074991220;
    uint256 constant PUB_42_Y = 3532713629061257151468908695442338192630185427851725277413245047659375017349;
    uint256 constant PUB_43_X = 6378962287004197396308146750071732486305451817009818615885331593415988556403;
    uint256 constant PUB_43_Y = 6964413374787019157629087442872857959585208253780350861467942755836601693995;
    uint256 constant PUB_44_X = 3803821212721190061800228986803015945736968608500599385904724280773297135288;
    uint256 constant PUB_44_Y = 12484741971748264321398147452957023303642788109177498470754841225973226281238;
    uint256 constant PUB_45_X = 14428904838073821555613710493911244147617518107463850404932840019314990335733;
    uint256 constant PUB_45_Y = 19663002401419972748576490947079318188712712058400701577059464219174199309128;
    uint256 constant PUB_46_X = 15760959316779117314590585228433241430688458615487702256720962070286005772544;
    uint256 constant PUB_46_Y = 8084892290287973976178398481298804813513918842024862051424447406370475396751;
    uint256 constant PUB_47_X = 18726607956539587750226777674197335844496820830502218774305093655395083734671;
    uint256 constant PUB_47_Y = 4816808985603655482535050848990685735918067305780055415988831264923266142227;
    uint256 constant PUB_48_X = 8744787309728062269760596212176564667406900409485537335312258674581770527969;
    uint256 constant PUB_48_Y = 7412427427324725826416876742271075100626887724878037108612296697589174415461;
    uint256 constant PUB_49_X = 12696616463057662243853199733456058950983747599720541877613225840832326290514;
    uint256 constant PUB_49_Y = 21854911908053257694503756693477483865101050971436385461808573829768511094292;
    uint256 constant PUB_50_X = 16286985377614932484834988270660504318535353742521468725586963373869735543937;
    uint256 constant PUB_50_Y = 16609366444688677974790646417977972967485846382131288444292429626143417847934;
    uint256 constant PUB_51_X = 13827511316289828282312497391076490499629871267192916831986970253917762079841;
    uint256 constant PUB_51_Y = 19168782339577310431054473623895183016649977979994249468054726977037496563260;
    uint256 constant PUB_52_X = 5098402231074052840208756114168405406538658256650652676527454934659442867127;
    uint256 constant PUB_52_Y = 4361508630125457939651322054145891320763606764808700613186363418849737991977;
    uint256 constant PUB_53_X = 2994973426254449474852582050473734910084801163999118959109789613658631982159;
    uint256 constant PUB_53_Y = 5253336263943083190181174381179610018916593121987108636303958920421595199310;
    uint256 constant PUB_54_X = 2378363805875028284730869830718921726785040988865326731233371380569380512494;
    uint256 constant PUB_54_Y = 8526700470210531420892400158843152409048245768238407964017030838405228798453;
    uint256 constant PUB_55_X = 902550265967766128089473330012127969040798429596628677061137011411988340400;
    uint256 constant PUB_55_Y = 10183674086585524360149624600986889002422816565517597597982188447454009042384;
    uint256 constant PUB_56_X = 15741540691843932704527739097148705361674655241810124630848904368479475482201;
    uint256 constant PUB_56_Y = 18336193677763676713299284388736801669462388524863317092496830782085483591179;
    uint256 constant PUB_57_X = 9063405282765575254133507207016974715106784071798346811983291952764945640258;
    uint256 constant PUB_57_Y = 4953834184388633031597037828821564473141139684116173043251660363019129207554;
    uint256 constant PUB_58_X = 9139203354022929793373018603312120630413734047536597719179301889232038455230;
    uint256 constant PUB_58_Y = 3695779781304488345344183758618949048103403492829026210274099971624229053681;
    uint256 constant PUB_59_X = 11084684105093461918362874607460533203450576274567937554071876830672641013024;
    uint256 constant PUB_59_Y = 12757231628524509696900446526907443586975636286898859953009407648586811567452;
    uint256 constant PUB_60_X = 6285052704487799316285209284235448823838683320451344827563344786471798392368;
    uint256 constant PUB_60_Y = 4634702790565773307254558390612153356214770728049295717851439113816786287300;
    uint256 constant PUB_61_X = 19480446361530718656551400395995666180385642825592163758216666473101482425032;
    uint256 constant PUB_61_Y = 1759136336540603613837613638179035840363964416851420923829222577753381064012;
    uint256 constant PUB_62_X = 4318817290765165624618804056762793023020189771734635246274371797785733797601;
    uint256 constant PUB_62_Y = 6580278832300418207279644602075606011415128066132324985910992824277623982845;
    uint256 constant PUB_63_X = 1904779737422858333080194200860505315758755736282557047535170425068129928747;
    uint256 constant PUB_63_Y = 6031687886442644321553320869208043639590996947229627296613855126920866693527;
    uint256 constant PUB_64_X = 5594040139053468018023617985980626177963950550572058578462825379770458108603;
    uint256 constant PUB_64_Y = 14860348717789622311179898734292589005737800614267333649882241971106185276368;
    uint256 constant PUB_65_X = 9212065205030025350571587075719109280030333506967524851817655960597202794921;
    uint256 constant PUB_65_Y = 3317855781449574077915907155109603800870662122424377353032383484852124454292;
    uint256 constant PUB_66_X = 1445955063067289832859214291301143919397282982492831071331042318755244215718;
    uint256 constant PUB_66_Y = 11750218932239199426691899443650125033095657664130929787253149876750743698890;
    uint256 constant PUB_67_X = 1374844454407913690907741731061490126606719436604556817537808080214448985346;
    uint256 constant PUB_67_Y = 1174630057679277533045716898199354996909303760774881068273448580866707125198;
    uint256 constant PUB_68_X = 8932727186219529992752502882782818073053344481016871716682998040213213661187;
    uint256 constant PUB_68_Y = 5751818753615199752205292066277400640156373731230932108466165637491994919574;
    uint256 constant PUB_69_X = 17115345854587607698066404618836169075223908240256728559104063638846327645177;
    uint256 constant PUB_69_Y = 17279982724316291372061266411683342620677332347725110841611295930912248088239;
    uint256 constant PUB_70_X = 19882960086911723637057150008099843988679829820699702919168422310983463841626;
    uint256 constant PUB_70_Y = 9733444475862858014991851881324795752438326841522656633971513988294001259798;
    uint256 constant PUB_71_X = 14257007061604876008652692896664021615100316239947764814834687555690854198981;
    uint256 constant PUB_71_Y = 2085122881927723705095996265280318680227857295226350684671307778555668640079;
    uint256 constant PUB_72_X = 0;
    uint256 constant PUB_72_Y = 0;
    uint256 constant PUB_73_X = 0;
    uint256 constant PUB_73_Y = 0;
    uint256 constant PUB_74_X = 0;
    uint256 constant PUB_74_Y = 0;
    uint256 constant PUB_75_X = 0;
    uint256 constant PUB_75_Y = 0;
    uint256 constant PUB_76_X = 0;
    uint256 constant PUB_76_Y = 0;
    uint256 constant PUB_77_X = 0;
    uint256 constant PUB_77_Y = 0;
    uint256 constant PUB_78_X = 0;
    uint256 constant PUB_78_Y = 0;
    uint256 constant PUB_79_X = 0;
    uint256 constant PUB_79_Y = 0;
    uint256 constant PUB_80_X = 0;
    uint256 constant PUB_80_Y = 0;
    uint256 constant PUB_81_X = 0;
    uint256 constant PUB_81_Y = 0;
    uint256 constant PUB_82_X = 0;
    uint256 constant PUB_82_Y = 0;
    uint256 constant PUB_83_X = 0;
    uint256 constant PUB_83_Y = 0;
    uint256 constant PUB_84_X = 0;
    uint256 constant PUB_84_Y = 0;
    uint256 constant PUB_85_X = 0;
    uint256 constant PUB_85_Y = 0;
    uint256 constant PUB_86_X = 0;
    uint256 constant PUB_86_Y = 0;
    uint256 constant PUB_87_X = 0;
    uint256 constant PUB_87_Y = 0;
    uint256 constant PUB_88_X = 0;
    uint256 constant PUB_88_Y = 0;
    uint256 constant PUB_89_X = 0;
    uint256 constant PUB_89_Y = 0;
    uint256 constant PUB_90_X = 0;
    uint256 constant PUB_90_Y = 0;
    uint256 constant PUB_91_X = 0;
    uint256 constant PUB_91_Y = 0;
    uint256 constant PUB_92_X = 0;
    uint256 constant PUB_92_Y = 0;
    uint256 constant PUB_93_X = 0;
    uint256 constant PUB_93_Y = 0;
    uint256 constant PUB_94_X = 0;
    uint256 constant PUB_94_Y = 0;
    uint256 constant PUB_95_X = 0;
    uint256 constant PUB_95_Y = 0;
    uint256 constant PUB_96_X = 0;
    uint256 constant PUB_96_Y = 0;
    uint256 constant PUB_97_X = 0;
    uint256 constant PUB_97_Y = 0;
    uint256 constant PUB_98_X = 0;
    uint256 constant PUB_98_Y = 0;
    uint256 constant PUB_99_X = 0;
    uint256 constant PUB_99_Y = 0;
    uint256 constant PUB_100_X = 0;
    uint256 constant PUB_100_Y = 0;
    uint256 constant PUB_101_X = 0;
    uint256 constant PUB_101_Y = 0;
    uint256 constant PUB_102_X = 0;
    uint256 constant PUB_102_Y = 0;
    uint256 constant PUB_103_X = 0;
    uint256 constant PUB_103_Y = 0;
    uint256 constant PUB_104_X = 0;
    uint256 constant PUB_104_Y = 0;
    uint256 constant PUB_105_X = 0;
    uint256 constant PUB_105_Y = 0;
    uint256 constant PUB_106_X = 0;
    uint256 constant PUB_106_Y = 0;
    uint256 constant PUB_107_X = 0;
    uint256 constant PUB_107_Y = 0;
    uint256 constant PUB_108_X = 0;
    uint256 constant PUB_108_Y = 0;
    uint256 constant PUB_109_X = 0;
    uint256 constant PUB_109_Y = 0;
    uint256 constant PUB_110_X = 0;
    uint256 constant PUB_110_Y = 0;
    uint256 constant PUB_111_X = 0;
    uint256 constant PUB_111_Y = 0;
    uint256 constant PUB_112_X = 0;
    uint256 constant PUB_112_Y = 0;
    uint256 constant PUB_113_X = 0;
    uint256 constant PUB_113_Y = 0;
    uint256 constant PUB_114_X = 0;
    uint256 constant PUB_114_Y = 0;
    uint256 constant PUB_115_X = 0;
    uint256 constant PUB_115_Y = 0;
    uint256 constant PUB_116_X = 0;
    uint256 constant PUB_116_Y = 0;
    uint256 constant PUB_117_X = 0;
    uint256 constant PUB_117_Y = 0;
    uint256 constant PUB_118_X = 0;
    uint256 constant PUB_118_Y = 0;
    uint256 constant PUB_119_X = 0;
    uint256 constant PUB_119_Y = 0;
    uint256 constant PUB_120_X = 0;
    uint256 constant PUB_120_Y = 0;
    uint256 constant PUB_121_X = 0;
    uint256 constant PUB_121_Y = 0;
    uint256 constant PUB_122_X = 0;
    uint256 constant PUB_122_Y = 0;
    uint256 constant PUB_123_X = 0;
    uint256 constant PUB_123_Y = 0;
    uint256 constant PUB_124_X = 3556250713643308101441425397558473342857211420862260104108840268124992318011;
    uint256 constant PUB_124_Y = 7085073833854636476573149488208033055805879222651319408209850524825371302731;
    uint256 constant PUB_125_X = 2415239384365041665197128687580060511655585159540600582617775895274670506321;
    uint256 constant PUB_125_Y = 3824273314116266147417746004403731615859264925595037409621796595434595410008;
    uint256 constant PUB_126_X = 12658357822943122295484498501542190950940682815202190959080303053979695665741;
    uint256 constant PUB_126_Y = 10471170836335959866093211309377980069587902620785794337627994743072068756345;
    uint256 constant PUB_127_X = 1836649054849393852571720982739868168361638106381825958663573208521300508766;
    uint256 constant PUB_127_Y = 3037318732154875873709507848733058091561209421035950581124663305939465260333;
    uint256 constant PUB_128_X = 2020045675734157065771242774725445434533464472774465798643654522703388119741;
    uint256 constant PUB_128_Y = 7197381800437753770979708930658232280924744712393110063745008883914271798872;

    /// Negation in Fp.
    /// @notice Returns a number x such that a + x = 0 in Fp.
    /// @notice The input does not need to be reduced.
    /// @param a the base
    /// @return x the result
    function negate(uint256 a) internal pure returns (uint256 x) {
        unchecked {
            x = (P - (a % P)) % P; // Modulo is cheaper than branching
        }
    }

    /// Exponentiation in Fp.
    /// @notice Returns a number x such that a ^ e = x in Fp.
    /// @notice The input does not need to be reduced.
    /// @param a the base
    /// @param e the exponent
    /// @return x the result
    function exp(uint256 a, uint256 e) internal view returns (uint256 x) {
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)
            mstore(f, 0x20)
            mstore(add(f, 0x20), 0x20)
            mstore(add(f, 0x40), 0x20)
            mstore(add(f, 0x60), a)
            mstore(add(f, 0x80), e)
            mstore(add(f, 0xa0), P)
            success := staticcall(gas(), PRECOMPILE_MODEXP, f, 0xc0, f, 0x20)
            x := mload(f)
        }
        if (!success) {
            // Exponentiation failed.
            // Should not happen.
            revert ProofInvalid();
        }
    }

    /// Invertsion in Fp.
    /// @notice Returns a number x such that a * x = 1 in Fp.
    /// @notice The input does not need to be reduced.
    /// @notice Reverts with ProofInvalid() if the inverse does not exist
    /// @param a the input
    /// @return x the solution
    function invert_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_INVERSE_FP);
        if (mulmod(a, x, P) != 1) {
            // Inverse does not exist.
            // Can only happen during G2 point decompression.
            revert ProofInvalid();
        }
    }

    /// Square root in Fp.
    /// @notice Returns a number x such that x * x = a in Fp.
    /// @notice Will revert with InvalidProof() if the input is not a square
    /// or not reduced.
    /// @param a the square
    /// @return x the solution
    function sqrt_Fp(uint256 a) internal view returns (uint256 x) {
        x = exp(a, EXP_SQRT_FP);
        if (mulmod(x, x, P) != a) {
            // Square root does not exist or a is not reduced.
            // Happens when G1 point is not on curve.
            revert ProofInvalid();
        }
    }

    /// Square test in Fp.
    /// @notice Returns whether a number x exists such that x * x = a in Fp.
    /// @notice Will revert with InvalidProof() if the input is not a square
    /// or not reduced.
    /// @param a the square
    /// @return x the solution
    function isSquare_Fp(uint256 a) internal view returns (bool) {
        uint256 x = exp(a, EXP_SQRT_FP);
        return mulmod(x, x, P) == a;
    }

    /// Square root in Fp2.
    /// @notice Fp2 is the complex extension Fp[i]/(i^2 + 1). The input is
    /// a0 + a1 ⋅ i and the result is x0 + x1 ⋅ i.
    /// @notice Will revert with InvalidProof() if
    ///   * the input is not a square,
    ///   * the hint is incorrect, or
    ///   * the input coefficients are not reduced.
    /// @param a0 The real part of the input.
    /// @param a1 The imaginary part of the input.
    /// @param hint A hint which of two possible signs to pick in the equation.
    /// @return x0 The real part of the square root.
    /// @return x1 The imaginary part of the square root.
    function sqrt_Fp2(uint256 a0, uint256 a1, bool hint) internal view returns (uint256 x0, uint256 x1) {
        // If this square root reverts there is no solution in Fp2.
        uint256 d = sqrt_Fp(addmod(mulmod(a0, a0, P), mulmod(a1, a1, P), P));
        if (hint) {
            d = negate(d);
        }
        // If this square root reverts there is no solution in Fp2.
        x0 = sqrt_Fp(mulmod(addmod(a0, d, P), FRACTION_1_2_FP, P));
        x1 = mulmod(a1, invert_Fp(mulmod(x0, 2, P)), P);

        // Check result to make sure we found a root.
        // Note: this also fails if a0 or a1 is not reduced.
        if (a0 != addmod(mulmod(x0, x0, P), negate(mulmod(x1, x1, P)), P)
        ||  a1 != mulmod(2, mulmod(x0, x1, P), P)) {
            revert ProofInvalid();
        }
    }

    /// Compress a G1 point.
    /// @notice Reverts with InvalidProof if the coordinates are not reduced
    /// or if the point is not on the curve.
    /// @notice The point at infinity is encoded as (0,0) and compressed to 0.
    /// @param x The X coordinate in Fp.
    /// @param y The Y coordinate in Fp.
    /// @return c The compresed point (x with one signal bit).
    function compress_g1(uint256 x, uint256 y) internal view returns (uint256 c) {
        if (x >= P || y >= P) {
            // G1 point not in field.
            revert ProofInvalid();
        }
        if (x == 0 && y == 0) {
            // Point at infinity
            return 0;
        }

        // Note: sqrt_Fp reverts if there is no solution, i.e. the x coordinate is invalid.
        uint256 y_pos = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        if (y == y_pos) {
            return (x << 1) | 0;
        } else if (y == negate(y_pos)) {
            return (x << 1) | 1;
        } else {
            // G1 point not on curve.
            revert ProofInvalid();
        }
    }

    /// Decompress a G1 point.
    /// @notice Reverts with InvalidProof if the input does not represent a valid point.
    /// @notice The point at infinity is encoded as (0,0) and compressed to 0.
    /// @param c The compresed point (x with one signal bit).
    /// @return x The X coordinate in Fp.
    /// @return y The Y coordinate in Fp.
    function decompress_g1(uint256 c) internal view returns (uint256 x, uint256 y) {
        // Note that X = 0 is not on the curve since 0³ + 3 = 3 is not a square.
        // so we can use it to represent the point at infinity.
        if (c == 0) {
            // Point at infinity as encoded in EIP196 and EIP197.
            return (0, 0);
        }
        bool negate_point = c & 1 == 1;
        x = c >> 1;
        if (x >= P) {
            // G1 x coordinate not in field.
            revert ProofInvalid();
        }

        // Note: (x³ + 3) is irreducible in Fp, so it can not be zero and therefore
        //       y can not be zero.
        // Note: sqrt_Fp reverts if there is no solution, i.e. the point is not on the curve.
        y = sqrt_Fp(addmod(mulmod(mulmod(x, x, P), x, P), 3, P));
        if (negate_point) {
            y = negate(y);
        }
    }

    /// Compress a G2 point.
    /// @notice Reverts with InvalidProof if the coefficients are not reduced
    /// or if the point is not on the curve.
    /// @notice The G2 curve is defined over the complex extension Fp[i]/(i^2 + 1)
    /// with coordinates (x0 + x1 ⋅ i, y0 + y1 ⋅ i).
    /// @notice The point at infinity is encoded as (0,0,0,0) and compressed to (0,0).
    /// @param x0 The real part of the X coordinate.
    /// @param x1 The imaginary poart of the X coordinate.
    /// @param y0 The real part of the Y coordinate.
    /// @param y1 The imaginary part of the Y coordinate.
    /// @return c0 The first half of the compresed point (x0 with two signal bits).
    /// @return c1 The second half of the compressed point (x1 unmodified).
    function compress_g2(uint256 x0, uint256 x1, uint256 y0, uint256 y1)
    internal view returns (uint256 c0, uint256 c1) {
        if (x0 >= P || x1 >= P || y0 >= P || y1 >= P) {
            // G2 point not in field.
            revert ProofInvalid();
        }
        if ((x0 | x1 | y0 | y1) == 0) {
            // Point at infinity
            return (0, 0);
        }

        // Compute y^2
        // Note: shadowing variables and scoping to avoid stack-to-deep.
        uint256 y0_pos;
        uint256 y1_pos;
        {
            uint256 n3ab = mulmod(mulmod(x0, x1, P), P-3, P);
            uint256 a_3 = mulmod(mulmod(x0, x0, P), x0, P);
            uint256 b_3 = mulmod(mulmod(x1, x1, P), x1, P);
            y0_pos = addmod(FRACTION_27_82_FP, addmod(a_3, mulmod(n3ab, x1, P), P), P);
            y1_pos = negate(addmod(FRACTION_3_82_FP,  addmod(b_3, mulmod(n3ab, x0, P), P), P));
        }

        // Determine hint bit
        // If this sqrt fails the x coordinate is not on the curve.
        bool hint;
        {
            uint256 d = sqrt_Fp(addmod(mulmod(y0_pos, y0_pos, P), mulmod(y1_pos, y1_pos, P), P));
            hint = !isSquare_Fp(mulmod(addmod(y0_pos, d, P), FRACTION_1_2_FP, P));
        }

        // Recover y
        (y0_pos, y1_pos) = sqrt_Fp2(y0_pos, y1_pos, hint);
        if (y0 == y0_pos && y1 == y1_pos) {
            c0 = (x0 << 2) | (hint ? 2  : 0) | 0;
            c1 = x1;
        } else if (y0 == negate(y0_pos) && y1 == negate(y1_pos)) {
            c0 = (x0 << 2) | (hint ? 2  : 0) | 1;
            c1 = x1;
        } else {
            // G1 point not on curve.
            revert ProofInvalid();
        }
    }

    /// Decompress a G2 point.
    /// @notice Reverts with InvalidProof if the input does not represent a valid point.
    /// @notice The G2 curve is defined over the complex extension Fp[i]/(i^2 + 1)
    /// with coordinates (x0 + x1 ⋅ i, y0 + y1 ⋅ i).
    /// @notice The point at infinity is encoded as (0,0,0,0) and compressed to (0,0).
    /// @param c0 The first half of the compresed point (x0 with two signal bits).
    /// @param c1 The second half of the compressed point (x1 unmodified).
    /// @return x0 The real part of the X coordinate.
    /// @return x1 The imaginary poart of the X coordinate.
    /// @return y0 The real part of the Y coordinate.
    /// @return y1 The imaginary part of the Y coordinate.
    function decompress_g2(uint256 c0, uint256 c1)
    internal view returns (uint256 x0, uint256 x1, uint256 y0, uint256 y1) {
        // Note that X = (0, 0) is not on the curve since 0³ + 3/(9 + i) is not a square.
        // so we can use it to represent the point at infinity.
        if (c0 == 0 && c1 == 0) {
            // Point at infinity as encoded in EIP197.
            return (0, 0, 0, 0);
        }
        bool negate_point = c0 & 1 == 1;
        bool hint = c0 & 2 == 2;
        x0 = c0 >> 2;
        x1 = c1;
        if (x0 >= P || x1 >= P) {
            // G2 x0 or x1 coefficient not in field.
            revert ProofInvalid();
        }

        uint256 n3ab = mulmod(mulmod(x0, x1, P), P-3, P);
        uint256 a_3 = mulmod(mulmod(x0, x0, P), x0, P);
        uint256 b_3 = mulmod(mulmod(x1, x1, P), x1, P);

        y0 = addmod(FRACTION_27_82_FP, addmod(a_3, mulmod(n3ab, x1, P), P), P);
        y1 = negate(addmod(FRACTION_3_82_FP,  addmod(b_3, mulmod(n3ab, x0, P), P), P));

        // Note: sqrt_Fp2 reverts if there is no solution, i.e. the point is not on the curve.
        // Note: (X³ + 3/(9 + i)) is irreducible in Fp2, so y can not be zero.
        //       But y0 or y1 may still independently be zero.
        (y0, y1) = sqrt_Fp2(y0, y1, hint);
        if (negate_point) {
            y0 = negate(y0);
            y1 = negate(y1);
        }
    }

    /// Compute the public input linear combination.
    /// @notice Reverts with PublicInputNotInField if the input is not in the field.
    /// @notice Computes the multi-scalar-multiplication of the public input
    /// elements and the verification key including the constant term.
    /// @param input The public inputs. These are elements of the scalar field Fr.
    /// @param publicCommitments public inputs generated from pedersen commitments.
    /// @param commitments The Pedersen commitments from the proof.
    /// @return x The X coordinate of the resulting G1 point.
    /// @return y The Y coordinate of the resulting G1 point.
    function publicInputMSM(
        uint256[128] calldata input,
        uint256[1] memory publicCommitments,
        uint256[2] memory commitments
    )
    internal view returns (uint256 x, uint256 y) {
        // Note: The ECMUL precompile does not reject unreduced values, so we check this.
        // Note: Unrolling this loop does not cost much extra in code-size, the bulk of the
        //       code-size is in the PUB_ constants.
        // ECMUL has input (x, y, scalar) and output (x', y').
        // ECADD has input (x1, y1, x2, y2) and output (x', y').
        // We reduce commitments(if any) with constants as the first point argument to ECADD.
        // We call them such that ecmul output is already in the second point
        // argument to ECADD so we can have a tight loop.
        bool success = true;
        assembly ("memory-safe") {
            let f := mload(0x40)
            let g := add(f, 0x40)
            let s
            mstore(f, CONSTANT_X)
            mstore(add(f, 0x20), CONSTANT_Y)
            mstore(g, mload(commitments))
            mstore(add(g, 0x20), mload(add(commitments, 0x20)))
            success := and(success,  staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_0_X)
            mstore(add(g, 0x20), PUB_0_Y)
            s :=  calldataload(input)
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_1_X)
            mstore(add(g, 0x20), PUB_1_Y)
            s :=  calldataload(add(input, 32))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_2_X)
            mstore(add(g, 0x20), PUB_2_Y)
            s :=  calldataload(add(input, 64))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_3_X)
            mstore(add(g, 0x20), PUB_3_Y)
            s :=  calldataload(add(input, 96))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_4_X)
            mstore(add(g, 0x20), PUB_4_Y)
            s :=  calldataload(add(input, 128))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_5_X)
            mstore(add(g, 0x20), PUB_5_Y)
            s :=  calldataload(add(input, 160))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_6_X)
            mstore(add(g, 0x20), PUB_6_Y)
            s :=  calldataload(add(input, 192))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_7_X)
            mstore(add(g, 0x20), PUB_7_Y)
            s :=  calldataload(add(input, 224))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_8_X)
            mstore(add(g, 0x20), PUB_8_Y)
            s :=  calldataload(add(input, 256))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_9_X)
            mstore(add(g, 0x20), PUB_9_Y)
            s :=  calldataload(add(input, 288))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_10_X)
            mstore(add(g, 0x20), PUB_10_Y)
            s :=  calldataload(add(input, 320))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_11_X)
            mstore(add(g, 0x20), PUB_11_Y)
            s :=  calldataload(add(input, 352))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_12_X)
            mstore(add(g, 0x20), PUB_12_Y)
            s :=  calldataload(add(input, 384))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_13_X)
            mstore(add(g, 0x20), PUB_13_Y)
            s :=  calldataload(add(input, 416))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_14_X)
            mstore(add(g, 0x20), PUB_14_Y)
            s :=  calldataload(add(input, 448))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_15_X)
            mstore(add(g, 0x20), PUB_15_Y)
            s :=  calldataload(add(input, 480))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_16_X)
            mstore(add(g, 0x20), PUB_16_Y)
            s :=  calldataload(add(input, 512))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_17_X)
            mstore(add(g, 0x20), PUB_17_Y)
            s :=  calldataload(add(input, 544))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_18_X)
            mstore(add(g, 0x20), PUB_18_Y)
            s :=  calldataload(add(input, 576))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_19_X)
            mstore(add(g, 0x20), PUB_19_Y)
            s :=  calldataload(add(input, 608))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_20_X)
            mstore(add(g, 0x20), PUB_20_Y)
            s :=  calldataload(add(input, 640))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_21_X)
            mstore(add(g, 0x20), PUB_21_Y)
            s :=  calldataload(add(input, 672))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_22_X)
            mstore(add(g, 0x20), PUB_22_Y)
            s :=  calldataload(add(input, 704))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_23_X)
            mstore(add(g, 0x20), PUB_23_Y)
            s :=  calldataload(add(input, 736))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_24_X)
            mstore(add(g, 0x20), PUB_24_Y)
            s :=  calldataload(add(input, 768))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_25_X)
            mstore(add(g, 0x20), PUB_25_Y)
            s :=  calldataload(add(input, 800))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_26_X)
            mstore(add(g, 0x20), PUB_26_Y)
            s :=  calldataload(add(input, 832))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_27_X)
            mstore(add(g, 0x20), PUB_27_Y)
            s :=  calldataload(add(input, 864))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_28_X)
            mstore(add(g, 0x20), PUB_28_Y)
            s :=  calldataload(add(input, 896))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_29_X)
            mstore(add(g, 0x20), PUB_29_Y)
            s :=  calldataload(add(input, 928))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_30_X)
            mstore(add(g, 0x20), PUB_30_Y)
            s :=  calldataload(add(input, 960))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_31_X)
            mstore(add(g, 0x20), PUB_31_Y)
            s :=  calldataload(add(input, 992))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_32_X)
            mstore(add(g, 0x20), PUB_32_Y)
            s :=  calldataload(add(input, 1024))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_33_X)
            mstore(add(g, 0x20), PUB_33_Y)
            s :=  calldataload(add(input, 1056))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_34_X)
            mstore(add(g, 0x20), PUB_34_Y)
            s :=  calldataload(add(input, 1088))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_35_X)
            mstore(add(g, 0x20), PUB_35_Y)
            s :=  calldataload(add(input, 1120))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_36_X)
            mstore(add(g, 0x20), PUB_36_Y)
            s :=  calldataload(add(input, 1152))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_37_X)
            mstore(add(g, 0x20), PUB_37_Y)
            s :=  calldataload(add(input, 1184))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_38_X)
            mstore(add(g, 0x20), PUB_38_Y)
            s :=  calldataload(add(input, 1216))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_39_X)
            mstore(add(g, 0x20), PUB_39_Y)
            s :=  calldataload(add(input, 1248))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_40_X)
            mstore(add(g, 0x20), PUB_40_Y)
            s :=  calldataload(add(input, 1280))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_41_X)
            mstore(add(g, 0x20), PUB_41_Y)
            s :=  calldataload(add(input, 1312))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_42_X)
            mstore(add(g, 0x20), PUB_42_Y)
            s :=  calldataload(add(input, 1344))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_43_X)
            mstore(add(g, 0x20), PUB_43_Y)
            s :=  calldataload(add(input, 1376))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_44_X)
            mstore(add(g, 0x20), PUB_44_Y)
            s :=  calldataload(add(input, 1408))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_45_X)
            mstore(add(g, 0x20), PUB_45_Y)
            s :=  calldataload(add(input, 1440))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_46_X)
            mstore(add(g, 0x20), PUB_46_Y)
            s :=  calldataload(add(input, 1472))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_47_X)
            mstore(add(g, 0x20), PUB_47_Y)
            s :=  calldataload(add(input, 1504))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_48_X)
            mstore(add(g, 0x20), PUB_48_Y)
            s :=  calldataload(add(input, 1536))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_49_X)
            mstore(add(g, 0x20), PUB_49_Y)
            s :=  calldataload(add(input, 1568))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_50_X)
            mstore(add(g, 0x20), PUB_50_Y)
            s :=  calldataload(add(input, 1600))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_51_X)
            mstore(add(g, 0x20), PUB_51_Y)
            s :=  calldataload(add(input, 1632))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_52_X)
            mstore(add(g, 0x20), PUB_52_Y)
            s :=  calldataload(add(input, 1664))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_53_X)
            mstore(add(g, 0x20), PUB_53_Y)
            s :=  calldataload(add(input, 1696))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_54_X)
            mstore(add(g, 0x20), PUB_54_Y)
            s :=  calldataload(add(input, 1728))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_55_X)
            mstore(add(g, 0x20), PUB_55_Y)
            s :=  calldataload(add(input, 1760))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_56_X)
            mstore(add(g, 0x20), PUB_56_Y)
            s :=  calldataload(add(input, 1792))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_57_X)
            mstore(add(g, 0x20), PUB_57_Y)
            s :=  calldataload(add(input, 1824))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_58_X)
            mstore(add(g, 0x20), PUB_58_Y)
            s :=  calldataload(add(input, 1856))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_59_X)
            mstore(add(g, 0x20), PUB_59_Y)
            s :=  calldataload(add(input, 1888))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_60_X)
            mstore(add(g, 0x20), PUB_60_Y)
            s :=  calldataload(add(input, 1920))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_61_X)
            mstore(add(g, 0x20), PUB_61_Y)
            s :=  calldataload(add(input, 1952))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_62_X)
            mstore(add(g, 0x20), PUB_62_Y)
            s :=  calldataload(add(input, 1984))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_63_X)
            mstore(add(g, 0x20), PUB_63_Y)
            s :=  calldataload(add(input, 2016))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_64_X)
            mstore(add(g, 0x20), PUB_64_Y)
            s :=  calldataload(add(input, 2048))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_65_X)
            mstore(add(g, 0x20), PUB_65_Y)
            s :=  calldataload(add(input, 2080))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_66_X)
            mstore(add(g, 0x20), PUB_66_Y)
            s :=  calldataload(add(input, 2112))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_67_X)
            mstore(add(g, 0x20), PUB_67_Y)
            s :=  calldataload(add(input, 2144))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_68_X)
            mstore(add(g, 0x20), PUB_68_Y)
            s :=  calldataload(add(input, 2176))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_69_X)
            mstore(add(g, 0x20), PUB_69_Y)
            s :=  calldataload(add(input, 2208))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_70_X)
            mstore(add(g, 0x20), PUB_70_Y)
            s :=  calldataload(add(input, 2240))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_71_X)
            mstore(add(g, 0x20), PUB_71_Y)
            s :=  calldataload(add(input, 2272))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_72_X)
            mstore(add(g, 0x20), PUB_72_Y)
            s :=  calldataload(add(input, 2304))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_73_X)
            mstore(add(g, 0x20), PUB_73_Y)
            s :=  calldataload(add(input, 2336))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_74_X)
            mstore(add(g, 0x20), PUB_74_Y)
            s :=  calldataload(add(input, 2368))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_75_X)
            mstore(add(g, 0x20), PUB_75_Y)
            s :=  calldataload(add(input, 2400))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_76_X)
            mstore(add(g, 0x20), PUB_76_Y)
            s :=  calldataload(add(input, 2432))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_77_X)
            mstore(add(g, 0x20), PUB_77_Y)
            s :=  calldataload(add(input, 2464))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_78_X)
            mstore(add(g, 0x20), PUB_78_Y)
            s :=  calldataload(add(input, 2496))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_79_X)
            mstore(add(g, 0x20), PUB_79_Y)
            s :=  calldataload(add(input, 2528))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_80_X)
            mstore(add(g, 0x20), PUB_80_Y)
            s :=  calldataload(add(input, 2560))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_81_X)
            mstore(add(g, 0x20), PUB_81_Y)
            s :=  calldataload(add(input, 2592))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_82_X)
            mstore(add(g, 0x20), PUB_82_Y)
            s :=  calldataload(add(input, 2624))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_83_X)
            mstore(add(g, 0x20), PUB_83_Y)
            s :=  calldataload(add(input, 2656))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_84_X)
            mstore(add(g, 0x20), PUB_84_Y)
            s :=  calldataload(add(input, 2688))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_85_X)
            mstore(add(g, 0x20), PUB_85_Y)
            s :=  calldataload(add(input, 2720))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_86_X)
            mstore(add(g, 0x20), PUB_86_Y)
            s :=  calldataload(add(input, 2752))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_87_X)
            mstore(add(g, 0x20), PUB_87_Y)
            s :=  calldataload(add(input, 2784))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_88_X)
            mstore(add(g, 0x20), PUB_88_Y)
            s :=  calldataload(add(input, 2816))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_89_X)
            mstore(add(g, 0x20), PUB_89_Y)
            s :=  calldataload(add(input, 2848))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_90_X)
            mstore(add(g, 0x20), PUB_90_Y)
            s :=  calldataload(add(input, 2880))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_91_X)
            mstore(add(g, 0x20), PUB_91_Y)
            s :=  calldataload(add(input, 2912))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_92_X)
            mstore(add(g, 0x20), PUB_92_Y)
            s :=  calldataload(add(input, 2944))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_93_X)
            mstore(add(g, 0x20), PUB_93_Y)
            s :=  calldataload(add(input, 2976))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_94_X)
            mstore(add(g, 0x20), PUB_94_Y)
            s :=  calldataload(add(input, 3008))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_95_X)
            mstore(add(g, 0x20), PUB_95_Y)
            s :=  calldataload(add(input, 3040))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_96_X)
            mstore(add(g, 0x20), PUB_96_Y)
            s :=  calldataload(add(input, 3072))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_97_X)
            mstore(add(g, 0x20), PUB_97_Y)
            s :=  calldataload(add(input, 3104))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_98_X)
            mstore(add(g, 0x20), PUB_98_Y)
            s :=  calldataload(add(input, 3136))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_99_X)
            mstore(add(g, 0x20), PUB_99_Y)
            s :=  calldataload(add(input, 3168))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_100_X)
            mstore(add(g, 0x20), PUB_100_Y)
            s :=  calldataload(add(input, 3200))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_101_X)
            mstore(add(g, 0x20), PUB_101_Y)
            s :=  calldataload(add(input, 3232))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_102_X)
            mstore(add(g, 0x20), PUB_102_Y)
            s :=  calldataload(add(input, 3264))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_103_X)
            mstore(add(g, 0x20), PUB_103_Y)
            s :=  calldataload(add(input, 3296))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_104_X)
            mstore(add(g, 0x20), PUB_104_Y)
            s :=  calldataload(add(input, 3328))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_105_X)
            mstore(add(g, 0x20), PUB_105_Y)
            s :=  calldataload(add(input, 3360))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_106_X)
            mstore(add(g, 0x20), PUB_106_Y)
            s :=  calldataload(add(input, 3392))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_107_X)
            mstore(add(g, 0x20), PUB_107_Y)
            s :=  calldataload(add(input, 3424))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_108_X)
            mstore(add(g, 0x20), PUB_108_Y)
            s :=  calldataload(add(input, 3456))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_109_X)
            mstore(add(g, 0x20), PUB_109_Y)
            s :=  calldataload(add(input, 3488))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_110_X)
            mstore(add(g, 0x20), PUB_110_Y)
            s :=  calldataload(add(input, 3520))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_111_X)
            mstore(add(g, 0x20), PUB_111_Y)
            s :=  calldataload(add(input, 3552))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_112_X)
            mstore(add(g, 0x20), PUB_112_Y)
            s :=  calldataload(add(input, 3584))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_113_X)
            mstore(add(g, 0x20), PUB_113_Y)
            s :=  calldataload(add(input, 3616))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_114_X)
            mstore(add(g, 0x20), PUB_114_Y)
            s :=  calldataload(add(input, 3648))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_115_X)
            mstore(add(g, 0x20), PUB_115_Y)
            s :=  calldataload(add(input, 3680))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_116_X)
            mstore(add(g, 0x20), PUB_116_Y)
            s :=  calldataload(add(input, 3712))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_117_X)
            mstore(add(g, 0x20), PUB_117_Y)
            s :=  calldataload(add(input, 3744))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_118_X)
            mstore(add(g, 0x20), PUB_118_Y)
            s :=  calldataload(add(input, 3776))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_119_X)
            mstore(add(g, 0x20), PUB_119_Y)
            s :=  calldataload(add(input, 3808))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_120_X)
            mstore(add(g, 0x20), PUB_120_Y)
            s :=  calldataload(add(input, 3840))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_121_X)
            mstore(add(g, 0x20), PUB_121_Y)
            s :=  calldataload(add(input, 3872))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_122_X)
            mstore(add(g, 0x20), PUB_122_Y)
            s :=  calldataload(add(input, 3904))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_123_X)
            mstore(add(g, 0x20), PUB_123_Y)
            s :=  calldataload(add(input, 3936))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_124_X)
            mstore(add(g, 0x20), PUB_124_Y)
            s :=  calldataload(add(input, 3968))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_125_X)
            mstore(add(g, 0x20), PUB_125_Y)
            s :=  calldataload(add(input, 4000))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_126_X)
            mstore(add(g, 0x20), PUB_126_Y)
            s :=  calldataload(add(input, 4032))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_127_X)
            mstore(add(g, 0x20), PUB_127_Y)
            s :=  calldataload(add(input, 4064))
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))
            mstore(g, PUB_128_X)
            mstore(add(g, 0x20), PUB_128_Y)
            s := mload(publicCommitments)
            mstore(add(g, 0x40), s)
            success := and(success, lt(s, R))
            success := and(success, staticcall(gas(), PRECOMPILE_MUL, g, 0x60, g, 0x40))
            success := and(success, staticcall(gas(), PRECOMPILE_ADD, f, 0x80, f, 0x40))

            x := mload(f)
            y := mload(add(f, 0x20))
        }
        if (!success) {
            // Either Public input not in field, or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert PublicInputNotInField();
        }
    }

    /// Compress a proof.
    /// @notice Will revert with InvalidProof if the curve points are invalid,
    /// but does not verify the proof itself.
    /// @param proof The uncompressed Groth16 proof. Elements are in the same order as for
    /// verifyProof. I.e. Groth16 points (A, B, C) encoded as in EIP-197.
    /// @param commitments Pedersen commitments from the proof.
    /// @param commitmentPok proof of knowledge for the Pedersen commitments.
    /// @return compressed The compressed proof. Elements are in the same order as for
    /// verifyCompressedProof. I.e. points (A, B, C) in compressed format.
    /// @return compressedCommitments compressed Pedersen commitments from the proof.
    /// @return compressedCommitmentPok compressed proof of knowledge for the Pedersen commitments.
    function compressProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok
    )
    public view returns (
        uint256[4] memory compressed,
        uint256[1] memory compressedCommitments,
        uint256 compressedCommitmentPok
    ) {
        compressed[0] = compress_g1(proof[0], proof[1]);
        (compressed[2], compressed[1]) = compress_g2(proof[3], proof[2], proof[5], proof[4]);
        compressed[3] = compress_g1(proof[6], proof[7]);
        compressedCommitments[0] = compress_g1(commitments[0], commitments[1]);
        compressedCommitmentPok = compress_g1(commitmentPok[0], commitmentPok[1]);
    }

    /// Verify a Groth16 proof with compressed points.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param compressedProof the points (A, B, C) in compressed format
    /// matching the output of compressProof.
    /// @param compressedCommitments compressed Pedersen commitments from the proof.
    /// @param compressedCommitmentPok compressed proof of knowledge for the Pedersen commitments.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyCompressedProof(
        uint256[4] calldata compressedProof,
        uint256[1] calldata compressedCommitments,
        uint256 compressedCommitmentPok,
        uint256[128] calldata input
    ) public view {
        uint256[1] memory publicCommitments;
        uint256[2] memory commitments;
        uint256[24] memory pairings;
        {
            (commitments[0], commitments[1]) = decompress_g1(compressedCommitments[0]);
            (uint256 Px, uint256 Py) = decompress_g1(compressedCommitmentPok);

            uint256[] memory publicAndCommitmentCommitted;
            publicAndCommitmentCommitted = new uint256[](60);
            assembly ("memory-safe") {
                let publicAndCommitmentCommittedOffset := add(publicAndCommitmentCommitted, 0x20)
                calldatacopy(add(publicAndCommitmentCommittedOffset, 0), add(input, 0), 512)
                calldatacopy(add(publicAndCommitmentCommittedOffset, 512), add(input, 1024), 1280)
                calldatacopy(add(publicAndCommitmentCommittedOffset, 1792), add(input, 3968), 128)
            }

            publicCommitments[0] = uint256(
                keccak256(
                    abi.encodePacked(
                        commitments[0],
                        commitments[1],
                        publicAndCommitmentCommitted
                    )
                )
            ) % R;
            // Commitments
            pairings[ 0] = commitments[0];
            pairings[ 1] = commitments[1];
            pairings[ 2] = PEDERSEN_GSIGMANEG_X_1;
            pairings[ 3] = PEDERSEN_GSIGMANEG_X_0;
            pairings[ 4] = PEDERSEN_GSIGMANEG_Y_1;
            pairings[ 5] = PEDERSEN_GSIGMANEG_Y_0;
            pairings[ 6] = Px;
            pairings[ 7] = Py;
            pairings[ 8] = PEDERSEN_G_X_1;
            pairings[ 9] = PEDERSEN_G_X_0;
            pairings[10] = PEDERSEN_G_Y_1;
            pairings[11] = PEDERSEN_G_Y_0;

            // Verify pedersen commitments
            bool success;
            assembly ("memory-safe") {
                let f := mload(0x40)

                success := staticcall(gas(), PRECOMPILE_VERIFY, pairings, 0x180, f, 0x20)
                success := and(success, mload(f))
            }
            if (!success) {
                revert CommitmentInvalid();
            }
        }

        {
            (uint256 Ax, uint256 Ay) = decompress_g1(compressedProof[0]);
            (uint256 Bx0, uint256 Bx1, uint256 By0, uint256 By1) = decompress_g2(compressedProof[2], compressedProof[1]);
            (uint256 Cx, uint256 Cy) = decompress_g1(compressedProof[3]);
            (uint256 Lx, uint256 Ly) = publicInputMSM(
                input,
                publicCommitments,
                commitments
            );

            // Verify the pairing
            // Note: The precompile expects the F2 coefficients in big-endian order.
            // Note: The pairing precompile rejects unreduced values, so we won't check that here.
            // e(A, B)
            pairings[ 0] = Ax;
            pairings[ 1] = Ay;
            pairings[ 2] = Bx1;
            pairings[ 3] = Bx0;
            pairings[ 4] = By1;
            pairings[ 5] = By0;
            // e(C, -δ)
            pairings[ 6] = Cx;
            pairings[ 7] = Cy;
            pairings[ 8] = DELTA_NEG_X_1;
            pairings[ 9] = DELTA_NEG_X_0;
            pairings[10] = DELTA_NEG_Y_1;
            pairings[11] = DELTA_NEG_Y_0;
            // e(α, -β)
            pairings[12] = ALPHA_X;
            pairings[13] = ALPHA_Y;
            pairings[14] = BETA_NEG_X_1;
            pairings[15] = BETA_NEG_X_0;
            pairings[16] = BETA_NEG_Y_1;
            pairings[17] = BETA_NEG_Y_0;
            // e(L_pub, -γ)
            pairings[18] = Lx;
            pairings[19] = Ly;
            pairings[20] = GAMMA_NEG_X_1;
            pairings[21] = GAMMA_NEG_X_0;
            pairings[22] = GAMMA_NEG_Y_1;
            pairings[23] = GAMMA_NEG_Y_0;

            // Check pairing equation.
            bool success;
            uint256[1] memory output;
            assembly ("memory-safe") {
                success := staticcall(gas(), PRECOMPILE_VERIFY, pairings, 0x300, output, 0x20)
            }
            if (!success || output[0] != 1) {
                // Either proof or verification key invalid.
                // We assume the contract is correctly generated, so the verification key is valid.
                revert ProofInvalid();
            }
        }
    }

    /// Verify an uncompressed Groth16 proof.
    /// @notice Reverts with InvalidProof if the proof is invalid or
    /// with PublicInputNotInField the public input is not reduced.
    /// @notice There is no return value. If the function does not revert, the
    /// proof was successfully verified.
    /// @param proof the points (A, B, C) in EIP-197 format matching the output
    /// of compressProof.
    /// @param commitments the Pedersen commitments from the proof.
    /// @param commitmentPok the proof of knowledge for the Pedersen commitments.
    /// @param input the public input field elements in the scalar field Fr.
    /// Elements must be reduced.
    function verifyProof(
        uint256[8] calldata proof,
        uint256[2] calldata commitments,
        uint256[2] calldata commitmentPok,
        uint256[128] calldata input
    ) public view {
        // HashToField
        uint256[1] memory publicCommitments;
        uint256[] memory publicAndCommitmentCommitted;
        publicAndCommitmentCommitted = new uint256[](60);
        assembly ("memory-safe") {
            let publicAndCommitmentCommittedOffset := add(publicAndCommitmentCommitted, 0x20)
            calldatacopy(add(publicAndCommitmentCommittedOffset, 0), add(input, 0), 512)
            calldatacopy(add(publicAndCommitmentCommittedOffset, 512), add(input, 1024), 1280)
            calldatacopy(add(publicAndCommitmentCommittedOffset, 1792), add(input, 3968), 128)
        }

            publicCommitments[0] = uint256(
                keccak256(
                    abi.encodePacked(
                        commitments[0],
                        commitments[1],
                        publicAndCommitmentCommitted
                    )
                )
            ) % R;

        // Verify pedersen commitments
        bool success;
        assembly ("memory-safe") {
            let f := mload(0x40)

            calldatacopy(f, commitments, 0x40) // Copy Commitments
            mstore(add(f, 0x40), PEDERSEN_GSIGMANEG_X_1)
            mstore(add(f, 0x60), PEDERSEN_GSIGMANEG_X_0)
            mstore(add(f, 0x80), PEDERSEN_GSIGMANEG_Y_1)
            mstore(add(f, 0xa0), PEDERSEN_GSIGMANEG_Y_0)
            calldatacopy(add(f, 0xc0), commitmentPok, 0x40)
            mstore(add(f, 0x100), PEDERSEN_G_X_1)
            mstore(add(f, 0x120), PEDERSEN_G_X_0)
            mstore(add(f, 0x140), PEDERSEN_G_Y_1)
            mstore(add(f, 0x160), PEDERSEN_G_Y_0)

            success := staticcall(gas(), PRECOMPILE_VERIFY, f, 0x180, f, 0x20)
            success := and(success, mload(f))
        }
        if (!success) {
            revert CommitmentInvalid();
        }

        (uint256 x, uint256 y) = publicInputMSM(
            input,
            publicCommitments,
            commitments
        );

        // Note: The precompile expects the F2 coefficients in big-endian order.
        // Note: The pairing precompile rejects unreduced values, so we won't check that here.
        assembly ("memory-safe") {
            let f := mload(0x40) // Free memory pointer.

            // Copy points (A, B, C) to memory. They are already in correct encoding.
            // This is pairing e(A, B) and G1 of e(C, -δ).
            calldatacopy(f, proof, 0x100)

            // Complete e(C, -δ) and write e(α, -β), e(L_pub, -γ) to memory.
            // OPT: This could be better done using a single codecopy, but
            //      Solidity (unlike standalone Yul) doesn't provide a way to
            //      to do this.
            mstore(add(f, 0x100), DELTA_NEG_X_1)
            mstore(add(f, 0x120), DELTA_NEG_X_0)
            mstore(add(f, 0x140), DELTA_NEG_Y_1)
            mstore(add(f, 0x160), DELTA_NEG_Y_0)
            mstore(add(f, 0x180), ALPHA_X)
            mstore(add(f, 0x1a0), ALPHA_Y)
            mstore(add(f, 0x1c0), BETA_NEG_X_1)
            mstore(add(f, 0x1e0), BETA_NEG_X_0)
            mstore(add(f, 0x200), BETA_NEG_Y_1)
            mstore(add(f, 0x220), BETA_NEG_Y_0)
            mstore(add(f, 0x240), x)
            mstore(add(f, 0x260), y)
            mstore(add(f, 0x280), GAMMA_NEG_X_1)
            mstore(add(f, 0x2a0), GAMMA_NEG_X_0)
            mstore(add(f, 0x2c0), GAMMA_NEG_Y_1)
            mstore(add(f, 0x2e0), GAMMA_NEG_Y_0)

            // Check pairing equation.
            success := staticcall(gas(), PRECOMPILE_VERIFY, f, 0x300, f, 0x20)
            // Also check returned value (both are either 1 or 0).
            success := and(success, mload(f))
        }
        if (!success) {
            // Either proof or verification key invalid.
            // We assume the contract is correctly generated, so the verification key is valid.
            revert ProofInvalid();
        }
    }
}
