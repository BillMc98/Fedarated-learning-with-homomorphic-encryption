#include "palisade.h"

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/ckks/ckks-ser.h"

using namespace lbcrypto;

const std::string DATAFOLDER = "demoData";

int main(int argc, char** argv) {

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


  double input;
  int numberOfVectors = 0;
  int y = std::stoi(argv[1]);
  int elementsInVector = (8192/y <= 0) ? 8192:y*(8192/y);
  vector<vector<double>> weights;
  std::ifstream infile(std::string(DATAFOLDER + "/weights.txt"));
  
  if (infile >> input){
    do {
      ++numberOfVectors;
      vector<double> w;
      w.push_back(input);
      for (int j=0; j<elementsInVector-1 && (infile >> input); ++j){
        w.push_back(input);
      }
      weights.push_back(w);
    } while(infile >> input);
  }
  else {
    std::cout << "No file found for encryption" << std::endl;
  }

  // std::ofstream output(DATAFOLDER + "/test.txt");
  // std::cout.precision(20);
  // if (output.is_open()){
  //   output << weights;
  // }


  LPPublicKey<DCRTPoly> pk;
  if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk,
                                  SerType::BINARY) == false) {
    std::cerr << "Could not read public key" << std::endl;
    return 1;
  }
  // Encryption
  // Plaintext vector is encoded
  for (int i=0; i<numberOfVectors; ++i){
    Plaintext plaintext = cc->MakeCKKSPackedPlaintext(weights[i]);
    auto ciphertext = cc->Encrypt(pk, plaintext);
    if (!Serial::SerializeToFile(DATAFOLDER + "/" + "ciphertextWeights" + std::to_string(i) + ".txt",
                                ciphertext, SerType::BINARY)) {
      std::cerr
          << "Error writing serialization of ciphertext"
          << std::endl;
      return 1;
    }
  }

  return 0;
}
