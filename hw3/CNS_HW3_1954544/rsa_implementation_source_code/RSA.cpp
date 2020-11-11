#include <iostream>
#include <fstream>
#include <gmpxx.h>

int file_size = 0;

/*
 * Generate random large prime number
 */
mpz_class generate_random_prime(const int &size)
{
    gmp_randclass rand(gmp_randinit_mt);
    rand.seed(time(NULL));
    mpz_class random_p;
    while (!mpz_probab_prime_p(random_p.get_mpz_t(), 25))
    {
        random_p = rand.get_z_bits(size);
    }

    return random_p;
}

/*
 * Recursive Extended Euclidean Algorithm for generating decryption key: d
 */
void eea(const mpz_class &a, const mpz_class &mod, mpz_class &x, mpz_class &y)  
{
    if (a == 0)  
    {  
        x = 0, y = 1;  
        return;
    }  
    mpz_class x1, y1;
    eea(mod%a, a, x1, y1);
    x = y1 - x1*(mod/a);
    y = x1;
}

/*
 * Find the Modular Inverse of e with respect to phi
 * using Extended Euclidean Algorithm(eea)
 */
mpz_class generate_d(const mpz_class &e, const mpz_class &phi)
{
    mpz_class s, t;
    eea(e, phi, t, s);
    return (t%phi + phi) % phi;
}

/*
 * Read data from file into string 
 */
void read_file(const std::string &input_file_name, std::string &data)
{
    std::ifstream input_file(input_file_name);
    
    input_file.seekg(0, std::ios::end);
    file_size = input_file.tellg();
    input_file.seekg(0);

    if (input_file.is_open())
    {
        std::string line;
        while (getline(input_file, line))
        {
            for (int i = 0; i < line.length(); ++i)
            {
                data += line[i];
            }
            data += "\n";
        }
    }
    else
    {
        std::cout << " ! ! ! Unable to open file ! ! ! " << "\n";
    }

    input_file.close();
}

/*
 * Write data from string into file
 */
void write_file(const std::string &output_file_name, std::string &data)
{
    std::ofstream output_file;
    output_file.open(output_file_name);
    output_file << data;
    output_file.close();
}

/*
 * Modular exponentiation operation(right-to-left binary exponentiation method)
 */
mpz_class modular_exponentiation(mpz_class base, mpz_class exponent, const mpz_class &modulo)
{
    mpz_class result = 1;
    base = base % modulo;

    while (exponent > 0)
    {
        if (exponent % 2 == 1)
        {
            result = (result*base) % modulo;
        }
        base = (base*base) % modulo;
        exponent = exponent / 2;
    }

    return result;
}

/*
 * RSA encryption operation 
 */
void rsa_encrypt(const std::string &data, const std::string &output_file_name, const mpz_class &e, const mpz_class &n)
{
    std::string encrypted_data;
    mpz_class decimal_data = (int)data[0];
    for (int i = 1; i < data.length(); ++i)
    {
        decimal_data = decimal_data*1000 + (unsigned char)data[i];
    }
    
    mpz_class mod_exp_result = modular_exponentiation(decimal_data, e, n);
    encrypted_data += mod_exp_result.get_str();

    write_file(output_file_name, encrypted_data);
}

/*
 * RSA decryption operation
 */
void rsa_decrypt(const std::string &data, const std::string &output_file_name, const mpz_class &d, const mpz_class &n)
{
    std::string decrypted_data;
    mpz_class decimal_data;
    decimal_data.set_str(data, 10);

    mpz_class mod_exp_result = modular_exponentiation(decimal_data, d, n);
    while (mod_exp_result != 0)
    {
        mpz_class temp = mod_exp_result%1000;
        decrypted_data += temp.get_si();
        mod_exp_result = mod_exp_result / 1000;
    }
    std::reverse(decrypted_data.begin(), decrypted_data.end());

    write_file(output_file_name, decrypted_data);
}

int main(int argc, char *argv[])
{
    if (argc == 5 && std::string(argv[1]) == "-g")              //key generation
    {
        mpz_class q = generate_random_prime(std::stoi(std::string(argv[4]))/2);
        mpz_class p;
        mpz_nextprime(p.get_mpz_t(), q.get_mpz_t());

        mpz_class n = p * q;
        mpz_class phi = (p-1) * (q-1);
        mpz_class e = 65537;
        mpz_class d = generate_d(e, phi);

        std::string publickey = std::string(argv[4])+"-"+e.get_str()+"|"+n.get_str();
        write_file(std::string(argv[2]), publickey);

        std::string privatekey = d.get_str()+"|"+n.get_str();
        write_file(std::string(argv[3]), privatekey);

        std::cout << "------------------------------------------------" << "\n";
        std::cout << " * * * Public and private keys generated. * * * " << "\n";
        std::cout << "------------------------------------------------" << "\n";
    }
    else if (argc == 5 && std::string(argv[1]) == "-e")         //encryption
    {
        std::string data;
        read_file(std::string(argv[2]), data);
        int data_file_size = file_size;

        std::string publickey;
        read_file(std::string(argv[4]), publickey);

        if (data_file_size >= std::stoi(publickey.substr(0, publickey.find('-')))/8)
        {
            std::cout << " ! ! ! DATA IS TOO LARGE FOR KEY SIZE ! ! ! " << "\n";
            return 0;
        }

        publickey.erase(0, publickey.find('-')+1);
        std::string publickey_n = publickey.substr(publickey.find('|')+1);
        std::string publickey_e = publickey.erase(publickey.find('|'));
        mpz_class e(publickey_e, 10);
        mpz_class n(publickey_n, 10);

        rsa_encrypt(data, std::string(argv[3]), e, n);

        std::cout << "----------------------------------------------" << "\n";
        std::cout << " * * * Data was successfully encrypted. * * * " << "\n";
        std::cout << "----------------------------------------------" << "\n";
    }
    else if (argc == 5 && std::string(argv[1]) == "-d")         //decryption
    {
        std::string data;
        read_file(std::string(argv[2]), data);

        std::string privatekey;
        read_file(std::string(argv[4]), privatekey);
        std::string privatekey_n = privatekey.substr(privatekey.find('|')+1);
        std::string privatekey_d = privatekey.erase(privatekey.find('|'));
        mpz_class d(privatekey_d, 10);
        mpz_class n(privatekey_n, 10);

        rsa_decrypt(data, std::string(argv[3]), d, n);

        std::cout << "----------------------------------------------" << "\n";
        std::cout << " * * * Data was successfully decrypted. * * * " << "\n";
        std::cout << "----------------------------------------------" << "\n";
    }
    else
    {
        std::cout << " ! ! ! INVALID COMMAND ARGUMENTS ! ! ! " << "\n";
        std::cout << " - KEY GENERATION: ./RSA -g <publickey file> <privatekey file> <size of n in bits>" << "\n";
        std::cout << " - ENCRYPTION:     ./RSA -e <input file> <output file> <publickey file>" << "\n";
        std::cout << " - DECRYPTION:     ./RSA -d <input file> <output file> <privatekey file>" << "\n";
    }

    return 0;
}