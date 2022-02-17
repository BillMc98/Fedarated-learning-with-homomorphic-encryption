#include "palisade.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/ckks/ckks-ser.h"

using namespace lbcrypto;

const std::string DATAFOLDER = "demoData";

int main(){

  // Set the main parameters
  SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 2;
  uint32_t scaleFactorBits = 50;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          depth, scaleFactorBits, 8192, securityLevel, 16384);

  // Enable features that you wish to use
  cc->Enable(ENCRYPTION);
  cc->Enable(SHE);
  cc->Enable(LEVELEDSHE);
  cc->Enable(MULTIPARTY);

  LPPublicKey<DCRTPoly> pk;
  if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk,
                                  SerType::BINARY) == false) {
    std::cerr << "Could not read public key" << std::endl;
    return 1;
  }

  // std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt",
  //                      std::ios::in | std::ios::binary);
  // if (!emkeys.is_open()) {
  //   std::cerr << "I cannot read serialization from "
  //             << DATAFOLDER + "/key-eval-mult.txt" << std::endl;
  //   return 1;
  // }
  // if (cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
  //   std::cerr << "Could not deserialize the eval mult key file" << std::endl;
  //   return 1;
  // }

  vector<Ciphertext<DCRTPoly>> ciphertext(28,0);
  for (int i=0; i<4; ++i){
    for (int j=0; j<7; ++j){
      if (Serial::DeserializeFromFile(DATAFOLDER + "/ciphertext" + std::to_string(i) + std::to_string(j) + ".txt", ciphertext[i*7+j],
                                      SerType::BINARY) == false) {
        std::cerr << "Could not read the ciphertext" << std::endl;
        return 1;
      }
    }
  }

  // Homomorphic additions
  Ciphertext<DCRTPoly> ciphertextAdd1;
  Ciphertext<DCRTPoly> ciphertextAdd2;
  vector<Ciphertext<DCRTPoly>> ciphertextAddResult(7,0);
  vector<Ciphertext<DCRTPoly>> ciphertextMultResult(7,0);
  for (int i=0; i<7; ++i){
    ciphertextAdd1 = cc->EvalAdd(ciphertext[0+i], ciphertext[7+i]);
    ciphertextAdd2 = cc->EvalAdd(ciphertext[14+i], ciphertext[21+i]);
    ciphertextAddResult[i] = cc->EvalAdd(ciphertextAdd1, ciphertextAdd2);
    ciphertextMultResult[i] = cc->EvalMult(ciphertextAddResult[i], 0.25);
  }

  // Decryption

  vector<vector<Ciphertext<DCRTPoly>>> ciphertextPartial(7);

  for (int j=1; j<5; ++j){
    LPPrivateKey<DCRTPoly> secretKey;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-private" + std::to_string(j) + ".txt", secretKey,
                                    SerType::BINARY) == false) {
      std::cerr << "Could not read secret key" << std::endl;
      return 1;
    }

  // Decrypt the result of multiplication
    if (j==1){
      for (int i=0; i<7; ++i){
        ciphertextPartial[i].push_back(cc->MultipartyDecryptLead(secretKey, {ciphertextMultResult[i]})[0]);
      }
    }
    else {
      for (int i=0; i<7; ++i){
        ciphertextPartial[i].push_back(cc->MultipartyDecryptMain(secretKey, {ciphertextMultResult[i]})[0]);
      }
    }
  }

  vector<Plaintext> plaintextMultResult(7,0);
  for (int i=0; i<7; ++i){
    cc->MultipartyDecryptFusion(ciphertextPartial[i], &plaintextMultResult[i]);
  }

  
  std::ofstream output(DATAFOLDER + "/Average.txt");
  if (output.is_open()){
    for(int i=0; i<7; ++i){
      output << plaintextMultResult[i];
    }
  }

  return 0;
}
