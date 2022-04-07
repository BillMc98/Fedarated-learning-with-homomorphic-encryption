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

  uint32_t n = std::stoi(argv[0]);
  uint32_t m = 6;
  uint32_t l = std::stoi(argv[1]);

  vector<vector<double>> x(n);
  vector<vector<double>> w(l);

  std::cout << x << std::endl << w << std::endl;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          depth, scaleFactorBits, 8192, securityLevel, 16384);
// Enable features that you wish to use
cc->Enable(ENCRYPTION);
cc->Enable(SHE);
cc->Enable(MULTIPARTY);

  LPPublicKey<DCRTPoly> pk;
  if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk,
                                  SerType::BINARY) == false) {
    std::cerr << "Could not read public key" << std::endl;
    return 1;
  }

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

cc->EvalSumKeyGen(keys.secretKey);

vector <Plaintext> plainX;
vector <Plaintext> plainW;
vector <Ciphertext<DCRTPoly>> cipherX;
vector <Ciphertext<DCRTPoly>> cipherW;
Ciphertext<DCRTPoly> cMul;
Ciphertext<DCRTPoly> cSum;
vector <Ciphertext<DCRTPoly>> cipherOut(n);
Plaintext out;

for (uint32_t j=0; j<n; ++j){
  plainX.push_back(cc->MakeCKKSPackedPlaintext(x[j]));
  cipherX.push_back(cc->Encrypt(keys.publicKey, plainX[j]));
}
for (uint32_t j=0; j<l; ++j){
  plainW.push_back(cc->MakeCKKSPackedPlaintext(w[j]));
  cipherW.push_back(cc->Encrypt(keys.publicKey, plainW[j]));
}

string temp;
//vector <double> temp = {0};
//cipherOut[0] = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(temp));
std::stringstream ss;
for (uint32_t i=0; i<n; ++i){
  for (uint32_t j=0; j<l; ++j){
    cMul = cc->EvalMult(cipherX[i], cipherW[j]);
    cSum = cc->EvalSum(cMul,m);
    cc->Decrypt(keys.secretKey, cSum, &out);
    out->SetLength(1);
    ss << out;
  //  cipherOut[0] = cc->EvalAdd(cipherOut[0],cSum);
  }
}

//  ss >> test;
//  std::cout << test << std::endl;

return 0;

}