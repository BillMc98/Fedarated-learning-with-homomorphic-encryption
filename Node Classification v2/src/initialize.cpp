#include "palisade.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/ckks/ckks-ser.h"


using namespace lbcrypto;

const std::string DATAFOLDER = "demoData";

int main(int argc, char** argv){
  // std::cout << "This program requres the subdirectory `" << DATAFOLDER
  //           << "' to exist, otherwise you will get "
  //           << "an error writing serializations." << std::endl;

  // Set the main parameters
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 2;
  uint32_t scaleFactorBits = 50;
  int test = std::stoi(argv[1]);
  int featureNum = (test < 8192) ? test:8192;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          depth, scaleFactorBits, 8192, securityLevel, 16384);

  // Enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);
  cc->Enable(MULTIPARTY);

  // Key Generation
  if (strtol(argv[2], nullptr, 10) == 2){
    // Initialize Public Key Containers
    LPKeyPair<DCRTPoly> kp1;
    LPKeyPair<DCRTPoly> kp2;
    // Round 1 (party A)
    kp1 = cc->KeyGen();

    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
    cc->EvalAtIndexKeyGen(kp1.secretKey, {featureNum});
    auto evalRotKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(cc->GetEvalAutomorphismKeyMap(kp1.secretKey->GetKeyTag()));

    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    // Round 2 (party B)
    kp2 = cc->MultipartyKeyGen(kp1.publicKey);
    auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
    //  "Joint evaluation multiplication key for (s_a + s_b) is generated..."
    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());
    // s_b*(s_a + s_b)
    auto evalMultBAB = cc->MultiMultEvalKey(evalMultAB, kp2.secretKey, kp2.publicKey->GetKeyTag());

    auto evalRotKeysB = cc->MultiEvalAtIndexKeyGen(kp2.secretKey, evalRotKeys, {featureNum}, kp2.publicKey->GetKeyTag());
    auto evalRotKeysJoin = cc->MultiAddEvalAutomorphismKeys(evalRotKeysB, evalRotKeys, kp2.publicKey->GetKeyTag());                                     
    cc->InsertEvalAutomorphismKey(evalRotKeysJoin);

    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());
    auto evalSumKeysAB = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());
    cc->InsertEvalSumKey(evalSumKeysAB);

    // Round 3 (party A)
    // s_a*(s_a + s_b)
    auto evalMultAAB = cc->MultiMultEvalKey(evalMultAB, kp1.secretKey, kp2.publicKey->GetKeyTag());
    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultAAB, evalMultBAB, evalMultAB->GetKeyTag());

    cc->InsertEvalMultKey({evalMultFinal});
    // Serialize the public keys
    if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt",
                                kp2.publicKey, SerType::BINARY)) {
      std::cerr << "Error writing serialization of public key to key-public.txt"
                << std::endl;
      return 1;
    }
    // Serialize the secret keys
    if (!Serial::SerializeToFile(DATAFOLDER + "/key-private1.txt",
                                kp1.secretKey, SerType::BINARY)) {
      std::cerr << "Error writing serialization of private key to key-private1.txt"
                << std::endl;
      return 1;
    }

    if (!Serial::SerializeToFile(DATAFOLDER + "/key-private2.txt",
                                kp2.secretKey, SerType::BINARY)) {
      std::cerr << "Error writing serialization of private key to key-private2.txt"
                << std::endl;
      return 1;
    }
    std::cout << "The secret keys have been serialized." << std::endl;
  }
  else if (strtol(argv[2], nullptr, 10) == 3){
    // Initialize Public Key Containers
    LPKeyPair<DCRTPoly> kp1;
    LPKeyPair<DCRTPoly> kp2;
    LPKeyPair<DCRTPoly> kp3;
    // Round 1 (party A)
    kp1 = cc->KeyGen();
    
    auto evalMultKey = cc->KeySwitchGen(kp1.secretKey, kp1.secretKey);
    cc->EvalAtIndexKeyGen(kp1.secretKey, {featureNum});
    auto evalRotKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(cc->GetEvalAutomorphismKeyMap(kp1.secretKey->GetKeyTag()));

    cc->EvalSumKeyGen(kp1.secretKey);
    auto evalSumKeys = std::make_shared<std::map<usint, LPEvalKey<DCRTPoly>>>(cc->GetEvalSumKeyMap(kp1.secretKey->GetKeyTag()));

    // Round 2 (party B)
    kp2 = cc->MultipartyKeyGen(kp1.publicKey);
    auto evalMultKey2 = cc->MultiKeySwitchGen(kp2.secretKey, kp2.secretKey, evalMultKey);
    //  "Joint evaluation multiplication key for (s_a + s_b) is generated..."
    auto evalMultAB = cc->MultiAddEvalKeys(evalMultKey, evalMultKey2, kp2.publicKey->GetKeyTag());

    auto evalRotKeysB = cc->MultiEvalAtIndexKeyGen(kp2.secretKey, evalRotKeys, {featureNum}, kp2.publicKey->GetKeyTag());
    auto evalRotKeysJ = cc->MultiAddEvalAutomorphismKeys(evalRotKeys, evalRotKeysB, kp2.publicKey->GetKeyTag());   
    
    auto evalSumKeysB = cc->MultiEvalSumKeyGen(kp2.secretKey, evalSumKeys, kp2.publicKey->GetKeyTag());
    auto evalSumKeysAB = cc->MultiAddEvalSumKeys(evalSumKeys, evalSumKeysB, kp2.publicKey->GetKeyTag());

    // Round 3 (party C)
    kp3 = cc->MultipartyKeyGen(kp2.publicKey);
    auto evalMultKey3 = cc->MultiKeySwitchGen(kp3.secretKey, kp3.secretKey, evalMultKey2);
    // (s_a + s_b + s_c)
    auto evalMultABC = cc->MultiAddEvalKeys(evalMultAB, evalMultKey3, kp3.publicKey->GetKeyTag());
    // s_c*(s_a + s_b + s_c)
    auto evalMultCABC = cc->MultiMultEvalKey(evalMultABC, kp3.secretKey, kp3.publicKey->GetKeyTag());

    auto evalRotKeysC = cc->MultiEvalAtIndexKeyGen(kp3.secretKey, evalRotKeysJ, {featureNum}, kp3.publicKey->GetKeyTag());
    auto evalRotKeysJoin = cc->MultiAddEvalAutomorphismKeys(evalRotKeysJ, evalRotKeysC, kp3.publicKey->GetKeyTag());                                     
    cc->InsertEvalAutomorphismKey(evalRotKeysJoin);

    auto evalSumKeysC = cc->MultiEvalSumKeyGen(kp3.secretKey, evalSumKeysAB, kp3.publicKey->GetKeyTag());
    auto evalSumKeysABC = cc->MultiAddEvalSumKeys(evalSumKeysAB, evalSumKeysC, kp3.publicKey->GetKeyTag());
    cc->InsertEvalSumKey(evalSumKeysABC);

    // Round 4 (party A)
    // s_a*(s_a + s_b + s_c)
    auto evalMultAABC = cc->MultiMultEvalKey(evalMultABC, kp1.secretKey, kp3.publicKey->GetKeyTag());

    // Round 5 (party B)
    // s_b*(s_a + s_b + s_c)
    auto evalMultBABC = cc->MultiMultEvalKey(evalMultABC, kp2.secretKey, kp3.publicKey->GetKeyTag());

    // s_a*(s_a + s_b + s_c) + s_b*(s_a + s_b + s_c)
    auto evalMultSemiFinal = cc->MultiAddEvalMultKeys(evalMultAABC, evalMultBABC, evalMultABC->GetKeyTag());
    // s_a*(s_a + s_b + s_c) + s_b*(s_a + s_b + s_c) + s_c*(s_a + s_b + s_c) = (s_a + s_b + s_c)^2
    auto evalMultFinal = cc->MultiAddEvalMultKeys(evalMultSemiFinal, evalMultCABC, evalMultABC->GetKeyTag());

    cc->InsertEvalMultKey({evalMultFinal});
    // Serialize the public keys
    if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt",
                                kp3.publicKey, SerType::BINARY)) {
      std::cerr << "Error writing serialization of public key to key-public.txt"
                << std::endl;
      return 1;
    }
    // Serialize the secret keys
    if (!Serial::SerializeToFile(DATAFOLDER + "/key-private1.txt",
                                kp1.secretKey, SerType::BINARY)) {
      std::cerr << "Error writing serialization of private key to key-private1.txt"
                << std::endl;
      return 1;
    }

    if (!Serial::SerializeToFile(DATAFOLDER + "/key-private2.txt",
                                kp2.secretKey, SerType::BINARY)) {
      std::cerr << "Error writing serialization of private key to key-private2.txt"
                << std::endl;
      return 1;
    }

    if (!Serial::SerializeToFile(DATAFOLDER + "/key-private3.txt",
                                kp3.secretKey, SerType::BINARY)) {
      std::cerr << "Error writing serialization of private key to key-private3.txt"
                << std::endl;
      return 1;
    }
    std::cout << "The secret keys have been serialized." << std::endl;

  }


  std::ofstream emkeyfile(DATAFOLDER + "/" + "key-eval-mult.txt",
                          std::ios::out | std::ios::binary);
  if (emkeyfile.is_open()) {
    if (cc->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false) {
      std::cerr << "Error writing serialization of the eval mult keys to "
                   "key-eval-mult.txt"
                << std::endl;
      return 1;
    }
        emkeyfile.close();
  } else {
    std::cerr << "Error serializing eval mult keys" << std::endl;
    return 1;
  }

  std::ofstream sumkeyfile(DATAFOLDER + "/" + "key-eval-sum.txt",
                          std::ios::out | std::ios::binary);
  if (sumkeyfile.is_open()) {
    if (cc->SerializeEvalSumKey(sumkeyfile, SerType::BINARY) == false) {
      std::cerr << "Error writing serialization of the eval sum keys to "
                   "key-eval-sum.txt"
                << std::endl;
      return 1;
    }
        sumkeyfile.close();
  } else {
    std::cerr << "Error serializing eval sum keys" << std::endl;
    return 1;
  }

  std::ofstream rotkeyfile(DATAFOLDER + "/" + "key-eval-rot.txt",
                          std::ios::out | std::ios::binary);
  if (rotkeyfile.is_open()) {
    if (cc->SerializeEvalAutomorphismKey(rotkeyfile, SerType::BINARY) == false) {
      std::cerr << "Error writing serialization of the eval rot keys to "
                   "key-eval-rot.txt"
                << std::endl;
      return 1;
    }
        rotkeyfile.close();
  } else {
    std::cerr << "Error serializing eval rot keys" << std::endl;
    return 1;
  }
  std::cout << "The public keys have been serialized." << std::endl;

  // Delete Params from previous runs
  std::ifstream ifile;
  ifile.open(DATAFOLDER + "/Params.txt");
  if (ifile)
    std::remove("demoData/Params.txt");


  return 0;
}