#include "gadgets/mimc.hpp"
#include "stubs.hpp"
#include <openssl/rand.h>
using namespace ethsnarks;
using namespace std;
using namespace std::chrono;

bool test_mimc_hash(size_t n)
{
    auto t1 = high_resolution_clock::now();
    ProtoboardT pb;

    std::vector<VariableT> var_m;
    var_m.reserve(n);
    for( size_t i = 0; i < n; i++ )
    {
        var_m.emplace_back(make_variable(pb, FieldT::random_element(), FMT("items.", "%d", i)));
    }

    pb.set_input_sizes(n);

    // Private inputs
    VariableT iv = make_variable(pb, FieldT("918403109389145570117360101535982733651217667914747213867238065296420114726"), "iv");

    MiMC_e7_hash_gadget the_gadget(pb, iv, var_m, "gadget");
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();

    if( ! pb.is_satisfied() ) {
        std::cerr << "Not satisfied!" << std::endl;
        return false;
    }

    auto t2 = high_resolution_clock::now(); 
    auto duration = duration_cast<milliseconds>(t2 - t1); 
    cout << "time cost - input size (bytes) = " << n * 32 << endl;
    cout << "time cost - generate: " << duration.count() << " milliseconds" << endl;
    std::cout << "time cost - " << pb.num_constraints() << " constraints" << std::endl;

    auto constraints = pb.get_constraint_system();
    auto keypair = libsnark::r1cs_gg_ppzksnark_zok_generator<ppT>(constraints);
    auto t3 = high_resolution_clock::now(); 
    duration = duration_cast<milliseconds>(t3 - t2); 
    cout << "time cost - setup: " << duration.count() << " milliseconds" << endl;

    auto primary_input = pb.primary_input();
    auto auxiliary_input = pb.auxiliary_input();
    auto proof = libsnark::r1cs_gg_ppzksnark_zok_prover<ppT>(keypair.pk, primary_input, auxiliary_input);

    auto t4 = high_resolution_clock::now(); 
    duration = duration_cast<milliseconds>(t4 - t3); 
    cout << "time cost - prove: " << duration.count() << " milliseconds" << endl;

    auto status = libsnark::r1cs_gg_ppzksnark_zok_verifier_strong_IC <ppT> (keypair.vk, primary_input, proof);
    auto t5 = high_resolution_clock::now(); 
    duration = duration_cast<milliseconds>(t5 - t4); 
    cout << "time cost - verify: " << duration.count() << " milliseconds" << endl;

    if( status )
        return true;

    return false;
}


int main( int argc, char **argv )
{
    ethsnarks::ppT::init_public_params();

    // size = 32 bytes, if n = 32, then data_size = 1KB
    vector<size_t> loop = {1, 2, 4, 8, 16, 32, 64, 128};
    for (auto &&i : loop)
    {
        if( ! test_mimc_hash(i) )
        {
            std::cerr << "FAIL (%d)" << i << std::endl;
            return 1;
        }  
    }

    std::cout << "OK\n";
    return 0;
}
