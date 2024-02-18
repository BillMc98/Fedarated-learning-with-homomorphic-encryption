#include "palisade.h"
using namespace lbcrypto;

// header files needed for serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "pubkeylp-ser.h"
#include "scheme/ckks/ckks-ser.h"

int main(int argc, char** argv){
// Set the main parameters
const std::string DATAFOLDER = "demoData";

// Instantiate the crypto context
SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 2;
  uint32_t scaleFactorBits = 50;

  int rows = std::stoi(argv[1]);
  int columns = std::stoi(argv[2]);
  int maxInnerVectors = 8192/columns;
  int innerVectors = std::stoi(argv[3]);
  int l = std::ceil(float(innerVectors)/maxInnerVectors);
  innerVectors = (innerVectors > maxInnerVectors) ? maxInnerVectors : innerVectors;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          depth, scaleFactorBits, 8192, securityLevel, 16384);
// Enable features that you wish to use
cc->Enable(ENCRYPTION);
cc->Enable(SHE);
cc->Enable(LEVELEDSHE);
cc->Enable(MULTIPARTY);
int numberOfClients = 2;


  std::ifstream emkeys(DATAFOLDER + "/key-eval-mult.txt",
                       std::ios::in | std::ios::binary);
  if (!emkeys.is_open()) {
    std::cerr << "I cannot read serialization from "
              << DATAFOLDER + "/key-eval-mult.txt" << std::endl;
    return 1;
  }
  if (cc->DeserializeEvalMultKey(emkeys, SerType::BINARY) == false) {
    std::cerr << "Could not deserialize the eval mult key file" << std::endl;
    return 1;
  }

  std::ifstream sumkeys(DATAFOLDER + "/key-eval-sum.txt",
                       std::ios::in | std::ios::binary);
  if (!sumkeys.is_open()) {
    std::cerr << "I cannot read serialization from "
              << DATAFOLDER + "/key-eval-sum.txt" << std::endl;
    return 1;
  }
  if (cc->DeserializeEvalSumKey(sumkeys, SerType::BINARY) == false) {
    std::cerr << "Could not deserialize the eval sum key file" << std::endl;
    return 1;
  }

  std::ifstream rotkeys(DATAFOLDER + "/key-eval-rot.txt",
                       std::ios::in | std::ios::binary);
  if (!rotkeys.is_open()) {
    std::cerr << "I cannot read serialization from "
              << DATAFOLDER + "/key-eval-rot.txt" << std::endl;
    return 1;
  }
  if (cc->DeserializeEvalAutomorphismKey(rotkeys, SerType::BINARY) == false) {
    std::cerr << "Could not deserialize the eval rot key file" << std::endl;
    return 1;
  }

vector<Ciphertext<DCRTPoly>> cipherX(rows,0);
vector<Ciphertext<DCRTPoly>> cipherW(l,0);

for (int i=0; i<rows; ++i){
  if (Serial::DeserializeFromFile(DATAFOLDER + "/ciphertext" + argv[4] + std::to_string(i) + ".txt", cipherX[i],
                                  SerType::BINARY) == false) {
    std::cerr << "Could not read the ciphertext" << std::endl;
    return 1;
  }
}

for (int i=0; i<l; ++i){
  if (Serial::DeserializeFromFile(DATAFOLDER + "/ciphertextWeights" + std::to_string(i) + ".txt", cipherW[i],
                                  SerType::BINARY) == false) {
    std::cerr << "Could not read the weights ciphertext " + std::to_string(i) << std::endl;
    return 1;
  }
}

vector<LPPrivateKey<DCRTPoly>> secretKey(numberOfClients,0);
for (int i=0; i<numberOfClients; ++i){
  if (Serial::DeserializeFromFile(DATAFOLDER + "/key-private" + std::to_string(i+1) + ".txt", secretKey[i],
                                  SerType::BINARY) == false) {
    std::cerr << "Could not read secret key" << std::endl;
    return 1;
  }
}

// Matrix multiplication and decryption should be done by different
// entities, but here they happen simultaneously for efficiency
std::ofstream output(DATAFOLDER + "/conv_output.txt");
for (int i=0; i<rows; ++i){
  for (int j=0; j<l; ++j){
    Ciphertext<DCRTPoly> cMul = cc->EvalMult(cipherX[i], cipherW[j]);
    Ciphertext<DCRTPoly> cSum = cc->EvalSum(cMul, columns);
    Plaintext out;
    for (int k=0; k<innerVectors; ++k){
      vector<Ciphertext<DCRTPoly>> ciphertextPartial;
      ciphertextPartial.push_back(cc->MultipartyDecryptLead(secretKey[0], {cSum})[0]);
      for (int client=1; client<numberOfClients; ++client){
        ciphertextPartial.push_back(cc->MultipartyDecryptMain(secretKey[client], {cSum})[0]); 
      }
      cc->MultipartyDecryptFusion(ciphertextPartial, &out);
      out->SetLength(2*rows);
      if (output.is_open())
        output << out;
      cMul = cc->EvalAtIndex(cMul, columns);
      cSum = cc->EvalSum(cMul,columns);
    }
  }
}

return 0;

}