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

  // Initialize Public Key Containers
  LPKeyPair<DCRTPoly> kp;

  // Generate a public/private key pair
  if (strtol(argv[1], nullptr, 10) == 1){
    kp = cc->KeyGen();
  }
  else{
    LPPublicKey<DCRTPoly> pk;
    if (Serial::DeserializeFromFile(DATAFOLDER + "/key-public.txt", pk,
                                    SerType::BINARY) == false) {
      std::cerr << "Could not read public key" << std::endl;
      return 1;
    }
    kp = cc->MultipartyKeyGen(pk);
  }

      // Serialize the public key
  if (!Serial::SerializeToFile(DATAFOLDER + "/key-public.txt",
                               kp.publicKey, SerType::BINARY)) {
    std::cerr << "Error writing serialization of public key to key-public.txt"
              << std::endl;
    return 1;
  }
  std::cout << "The public key has been serialized." << std::endl;

  // Serialize the secret keys
  if (!Serial::SerializeToFile(DATAFOLDER + "/key-private" + argv[1] + ".txt",
                               kp.secretKey, SerType::BINARY)) {
    std::cerr << "Error writing serialization of private key to key-private.txt"
              << std::endl;
    return 1;
  }

  std::cout << "The secret key has been serialized." << std::endl;

  // Delete Params from previous runs
  std::ifstream ifile;
  ifile.open(DATAFOLDER + "/Params.txt");
  if (ifile)
    std::remove("demoData/Params.txt");

  // Generate the relinearization key
  //cc->EvalMultKeyGen(kp.secretKey);

  // Serialize the relinearization (evaluation) key for homomorphic
  // multiplication
  //  std::ofstream emkeyfile(DATAFOLDER + "/" + "key-eval-mult.txt",
  //                          std::ios::out | std::ios::binary);
  // if (emkeyfile.is_open()) {
  //   if (cc->SerializeEvalMultKey(emkeyfile, SerType::BINARY) == false) {
  //     std::cerr << "Error writing serialization of the eval mult keys to "
  //                  "key-eval-mult.txt"
  //               << std::endl;
  //     return 1;
  //   }
  //   std::cout << "The eval mult keys have been serialized." << std::endl;
  //   emkeyfile.close();
  // } else {
  //   std::cerr << "Error serializing eval mult keys" << std::endl;
  //   return 1;
  // }

  return 0;
}