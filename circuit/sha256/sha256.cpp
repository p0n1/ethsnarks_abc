#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>

#include "gadgets/sha256_many.cpp"
#include "utils.hpp"
#include <openssl/rand.h>

using libsnark::digest_variable;
using libsnark::block_variable;
using libsnark::SHA256_digest_size;
using libsnark::SHA256_block_size;

using ethsnarks::ppT;
using namespace ethsnarks;
using namespace std::chrono;
using namespace std;


bool test_sha256_many(uint8_t *input_buffer, size_t input_len)
{
    auto t1 = high_resolution_clock::now();
    ProtoboardT pb;

    // Fill array of input bits
    VariableArrayT block;
    block.allocate(pb, input_len * 8, "block");
    const libff::bit_vector block_bits = bytes_to_bv(input_buffer, input_len);
    block.fill_with_bits(pb, block_bits);

    sha256_many the_gadget(pb, block, "the_gadget");
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();
    auto t2 = high_resolution_clock::now(); 
    auto duration = duration_cast<milliseconds>(t2 - t1); 
    cout << "time cost - input_len = " << input_len << endl;
    cout << "time cost - generate: " << duration.count() << " milliseconds" << endl;

    const auto constraints = pb.get_constraint_system();
    auto keypair = libsnark::r1cs_gg_ppzksnark_zok_generator<ppT>(constraints);
    auto t3 = high_resolution_clock::now(); 
    duration = duration_cast<milliseconds>(t3 - t2); 
    cout << "time cost - setup: " << duration.count() << " milliseconds" << endl;

    cout << "time cost - Number of R1CS constraints: " << constraints.num_constraints() << endl;
    auto proof = libsnark::r1cs_gg_ppzksnark_zok_prover<ethsnarks::ppT>(keypair.pk, pb.primary_input(), pb.auxiliary_input());
    auto t4 = high_resolution_clock::now(); 
    duration = duration_cast<milliseconds>(t4 - t3); 
    cout << "time cost - prove: " << duration.count() << " milliseconds" << endl;

    auto status = libsnark::r1cs_gg_ppzksnark_zok_verifier_strong_IC <ppT> (keypair.vk, pb.primary_input(), proof);
    auto t5 = high_resolution_clock::now(); 
    duration = duration_cast<milliseconds>(t5 - t4); 
    cout << "time cost - verify: " << duration.count() << " milliseconds" << endl;
    if( status )
        return true;

    return false;
}


bool test_sha256_rand(size_t n) {
    uint8_t *buffer = new uint8_t[n];

    if( RAND_bytes(buffer, n) != 1 ) {
        std::cerr << "Could not produce random bytes: " << n << std::endl;
        return false;
    }
    auto result = test_sha256_many(buffer, n);

    delete[] buffer;

    return result;
}

int main( int argc, char **argv )
{
	ppT::init_public_params();

    // size = 1 Byte, if input length = 1024, then input size = 1 KB
    vector<size_t> loop = {1024};
    for (auto &&i : loop)
    {
        if( ! test_sha256_rand(i) )
        {
            std::cerr << "FAIL (%d)" << i << std::endl;
            return 1;
        }  
    }

	std::cout << "OK" << std::endl;
	return 0;
}