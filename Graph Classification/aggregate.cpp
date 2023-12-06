#include "palisade.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/ckks/ckks-ser.h"

using namespace lbcrypto;

const std::string DATAFOLDER = "demoData";

int main(int argc, char** argv){

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

  std::ifstream infile(DATAFOLDER + "/Params.txt");
  int numberOfVectors;
  infile >> numberOfVectors;
  infile.close();
  int numberOfClients = std::stoi(argv[1]);

  vector<Ciphertext<DCRTPoly>> ciphertext(numberOfClients*numberOfVectors,0);
  for (int i=0; i<numberOfClients; ++i){
    for (int j=0; j<numberOfVectors; ++j){
      if (Serial::DeserializeFromFile(DATAFOLDER + "/weights" + std::to_string(i) + std::to_string(j) + ".txt", ciphertext[i*numberOfVectors+j],
                                      SerType::BINARY) == false) {
        std::cerr << "Could not read the weight ciphertext for aggregation" << std::endl;
        return 1;
      }
    }
  }

  // Homomorphic additions
  //Ciphertext<DCRTPoly> ciphertextAdd1;
  //Ciphertext<DCRTPoly> ciphertextAdd2;
  //vector<Ciphertext<DCRTPoly>> ciphertextAddResult(numberOfVectors,0);
  //vector<Ciphertext<DCRTPoly>> ciphertextMultResult(numberOfVectors,0);
  //for (int i=0; i<numberOfVectors; ++i){
  //  ciphertextAdd1 = cc->EvalAdd(ciphertext[i], ciphertext[numberOfVectors+i]);
  //  ciphertextAddResult[i] = cc->EvalAdd(ciphertextAdd1, ciphertext[2*numberOfVectors+i]);
  //  ciphertextMultResult[i] = cc->EvalMult(ciphertextAddResult[i], double(1)/3);
  //}

  int step = numberOfClients/2;
  bool isOdd = numberOfClients%2;
  while(step){
    vector<Ciphertext<DCRTPoly>> ciphertextAddResult;
      for (int i=0; i<numberOfVectors*step; ++i){
        ciphertextAddResult.push_back(cc->EvalAdd(ciphertext[i], ciphertext[step*numberOfVectors+i]));
      }
      if (isOdd){
        for (int i=0; i<numberOfVectors; ++i){
          ciphertextAddResult.push_back(ciphertext.end()[i-numberOfVectors]);
        }
        ++step;
      }
      ciphertext = ciphertextAddResult;
      isOdd = step%2;
      step = step/2;
  }
  vector<Ciphertext<DCRTPoly>> ciphertextMultResult(numberOfVectors,0);
  for (int i=0; i<numberOfVectors; ++i){
    ciphertextMultResult[i] = cc->EvalMult(ciphertext[i], double(1)/numberOfClients);
  }

  // Decryption

  vector<vector<Ciphertext<DCRTPoly>>> ciphertextPartial(numberOfVectors);

  for (int j=1; j<numberOfClients+1; ++j){
    LPPrivateKey<DCRTPoly> secretKey;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-private" + std::to_string(j) + ".txt", secretKey,
                                    SerType::BINARY) == false) {
      std::cerr << "Could not read secret key" << std::endl;
      return 1;
    }

  // Decrypt the result of multiplication
    if (j==1){
      for (int i=0; i<numberOfVectors; ++i){
        ciphertextPartial[i].push_back(cc->MultipartyDecryptLead(secretKey, {ciphertextMultResult[i]})[0]);
      }
    }
    else {
      for (int i=0; i<numberOfVectors; ++i){
        ciphertextPartial[i].push_back(cc->MultipartyDecryptMain(secretKey, {ciphertextMultResult[i]})[0]);
      }
    }
  }

  vector<Plaintext> plaintextMultResult(numberOfVectors,0);
  for (int i=0; i<numberOfVectors; ++i){
    cc->MultipartyDecryptFusion(ciphertextPartial[i], &plaintextMultResult[i]);
  }

  
  std::ofstream output(DATAFOLDER + "/Average.txt");
  if (output.is_open()){
    for(int i=0; i<numberOfVectors; ++i){
      output << plaintextMultResult[i];
    }
  }

  return 0;
}
