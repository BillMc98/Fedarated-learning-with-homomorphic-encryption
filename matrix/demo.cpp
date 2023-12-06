#include "palisade.h"
using namespace lbcrypto;

int main(){
// Set the main parameters

// Instantiate the crypto context
SecurityLevel securityLevel = HEStd_128_classic;
  uint32_t depth = 2;
  uint32_t scaleFactorBits = 50;
  
  double lower_bound = 0;
  double upper_bound = 10;
  uint32_t n = 100;
  uint32_t m = 4;
  uint32_t l = 80;
  
  vector<vector<double>> x(n);
  vector<vector<double>> w(l);

  std::uniform_real_distribution<double> unif(lower_bound,upper_bound);
  std::default_random_engine re;

  // for (uint32_t i=0; i<n/8+1; ++i){
  //   for (uint32_t k=0; k<8; ++k){
  //     for (uint32_t j=0; j<m; ++j){
  //       x[i].push_back(unif(re));
  //     }
  //   }
  // }
  // for (uint32_t i=0; i<l/8+1; ++i){
  //   for (uint32_t k=0; k<8; ++k){
  //     for (uint32_t j=0; j<m; ++j){
  //       w[i].push_back(unif(re));
  //     }
  //   }
  // }

    for (uint32_t i=0; i<n; ++i){
      for (uint32_t j=0; j<m; ++j){
        x[i].push_back(unif(re));
      }
    }
  for (uint32_t i=0; i<l; ++i){
      for (uint32_t j=0; j<m; ++j){
        w[i].push_back(unif(re));
      }
  }

   std::cout << x << std::endl << w << std::endl;

  // Instantiate the crypto context
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextCKKS(
          depth, scaleFactorBits, 8192, securityLevel, 16384);
// Enable features that you wish to use
cc->Enable(ENCRYPTION);
cc->Enable(SHE);

auto keys = cc->KeyGen();
cc->EvalMultKeyGen(keys.secretKey);
cc->EvalSumKeyGen(keys.secretKey);
cc->EvalAtIndexKeyGen(keys.secretKey, {-1, -int(m)});

vector <Plaintext> plainX;
vector <Plaintext> plainW;
vector <Ciphertext<DCRTPoly>> cipherX;
vector <Ciphertext<DCRTPoly>> cipherW;
Ciphertext<DCRTPoly> cMul;
Ciphertext<DCRTPoly> cSum;
vector <Ciphertext<DCRTPoly>> cipherOut(n);
Plaintext out;

auto start = std::chrono::high_resolution_clock::now();

for (uint32_t j=0; j<n; ++j){
  plainX.push_back(cc->MakeCKKSPackedPlaintext(x[j]));
  cipherX.push_back(cc->Encrypt(keys.publicKey, plainX[j]));
}
  // std::cout << plainX << std::endl;

for (uint32_t j=0; j<l; ++j){
  plainW.push_back(cc->MakeCKKSPackedPlaintext(w[j]));
  cipherW.push_back(cc->Encrypt(keys.publicKey, plainW[j]));
}

vector <Ciphertext<DCRTPoly>> cipherXX;
vector <Ciphertext<DCRTPoly>> cipherWW;

int counter = n-1;
for (uint32_t i=0; i<int(double(n)/8+0.5); ++i){
  cipherXX.push_back(cipherX[counter--]);

  for (uint32_t j=0; j<7&&counter>=0; ++j, --counter){
    cipherXX[i] = cc->EvalAtIndex(cipherXX[i], -int(m));
    cipherXX[i] = cc->EvalAdd(cipherX[counter], cipherXX[i]);
  }
}

counter = l-1;
for (uint32_t i=0; i<int(double(l)/8+0.5); ++i){
  cipherWW.push_back(cipherW[counter--]);

  for (uint32_t j=0; j<7&&counter>=0; ++j, --counter){
    cipherWW[i] = cc->EvalAtIndex(cipherWW[i], -int(m));
    cipherWW[i] = cc->EvalAdd(cipherW[counter], cipherWW[i]);
  }
}
string temp;
//vector <double> temp = {0};
//cipherOut[0] = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(temp));
std::stringstream ss;
for (uint32_t i=int(n/8+1); i<=0; --i){
  for (uint32_t j=int(double(l)/8+0.5); j<=0; --j){
    cMul = cc->EvalMult(cipherXX[i], cipherWW[j]);
    cSum = cc->EvalSum(cMul,m);
    for (uint32_t k=0; k<7; ++k){
      cc->Decrypt(keys.secretKey, cSum, &out);
      out->SetLength(1);
      ss << out;
      cMul = cc->EvalAtIndex(cMul, -int(m));
      cSum = cc->EvalSum(cMul,m);
    }
      cc->Decrypt(keys.secretKey, cSum, &out);
      out->SetLength(1);
      ss << out;
  //  cipherOut[0] = cc->EvalAdd(cipherOut[0],cSum);
  }
}

// for (uint32_t i=0; i<n; ++i){
//   for (uint32_t j=0; j<l; ++j){
//     cMul = cc->EvalMult(cipherX[i], cipherW[j]);
//     cSum = cc->EvalSum(cMul,m);
//     cc->Decrypt(keys.secretKey, cSum, &out);
//     out->SetLength(1);
//     ss << out;
//   //  cipherOut[0] = cc->EvalAdd(cipherOut[0],cSum);
//   }
// }
auto stop = std::chrono::high_resolution_clock::now();
std::cout << "Time taken by multiplication: " << std::chrono::duration_cast<std::chrono::seconds>(stop - start).count() << " seconds" << std::endl;

  string test;
  ss >> test;
  std::cout << test << std::endl;

return 0;

}