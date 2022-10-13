#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string> 
#include "sodium.h"
#include "crypto_sign.h"
#include <thread>
#include <chrono>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <algorithm>
#include "x86intrin.h"

using namespace std;
#pragma warning(disable : 4996)

#pragma intrinsic(__rdtsc)
#define NTEST 100000

void measured_function(volatile int* var) { (*var) = 1; }

using std::this_thread::sleep_for;

#define DEBUG 0

using namespace std;

using std::cout; using std::cerr;
using std::endl; using std::string;

//https://www.delftstack.com/howto/cpp/read-file-into-string-cpp/#:~:text=in%20C%2B%2B.-,Use%20istreambuf_iterator%20to%20Read%20File%20Into%20String%20in%20C%2B%2B,into%20a%20std%3A%3Astring%20.
string readFileIntoString(const string& path) {
    struct stat sb {};
    string res;

    FILE* input_file = fopen(path.c_str(), "r");
    if (input_file == nullptr) {
        perror("fopen");
    }

    stat(path.c_str(), &sb);
    res.resize(sb.st_size);
    fread(const_cast<char*>(res.data()), sb.st_size, 1, input_file);
    fclose(input_file);

    return res;
}

int verify(const char* file, const unsigned char publicKey[crypto_sign_PUBLICKEYBYTES]) {
    string file_contents;
    file_contents = readFileIntoString(file);
    unsigned long long file_length = file_contents.length();

    //if the fil has a bad sign
    if (file_length < crypto_sign_BYTES) {
        return 1;
    }

    string signature = file_contents.substr(0, crypto_sign_BYTES);
    file_contents = file_contents.substr(crypto_sign_BYTES, file_length);

    file_length = file_contents.length();

    unsigned char* message = new unsigned char[file_length + 1];

    std::copy(file_contents.begin(), file_contents.end(), message);
    message[file_contents.length()] = 0;

    unsigned char* sig = new unsigned char[crypto_sign_BYTES + 1];

    std::copy(signature.begin(), signature.end(), sig);
    sig[signature.length()] = 0;

    if (crypto_sign_verify_detached(sig, message, file_length, publicKey) != 0) {
        cout << "ERROR: SIGNATURE FAILED\n";
        return 1;
    }
    cout << "CORRECT SIGNATURE\n";

    delete[] message;
    delete[] sig;

    return 0;
}

int signFile(const char* original, const char* destiny, const unsigned char publicKey[crypto_sign_PUBLICKEYBYTES], const unsigned char privateKey[crypto_sign_SECRETKEYBYTES]) {
    string file_contents;
    file_contents = readFileIntoString(original);
    int file_length = file_contents.length();

    unsigned char* content = new unsigned char[file_length + 1]();

    std::copy(file_contents.begin(), file_contents.end(), content);
    content[file_contents.length()] = 0;

    unsigned char* signed_message = new unsigned char[crypto_sign_BYTES + file_length];
    unsigned long long signed_message_len;

    crypto_sign(signed_message, &signed_message_len, content, file_length, privateKey);

    unsigned char* unsigned_message = new unsigned char[file_length];
    unsigned long long unsigned_message_len;

    //error sign file
    if (crypto_sign_open(unsigned_message, &unsigned_message_len, signed_message, signed_message_len, publicKey) != 0) {
        return 1;
    }

    char* result = new char[crypto_sign_BYTES + file_length];

    for (unsigned int i = 0; i < crypto_sign_BYTES + file_length; i++) {
        result[i] = signed_message[i];
    }

    ofstream ofs;
    ofs.open(destiny, ios::app);
    ofs.write((char*)result, crypto_sign_BYTES + file_length);
    ofs.close();

    delete[] signed_message;
    delete[] unsigned_message;
    delete[] content;
    delete[] result;

    return 0;
}

int encrypt(const char* original, const char* destiny,unsigned char key[crypto_stream_chacha20_KEYBYTES]) {
    unsigned char buf[128];

    std::cout << std::setfill('0') << std::setw(2);
    std::cout.setf(std::ios::hex, std::ios::basefield);

    unsigned char* plaintext = NULL;
    unsigned char* ciphertext = NULL;
    unsigned char nonce[crypto_stream_chacha20_KEYBYTES];
    //unsigned char key[crypto_stream_chacha20_KEYBYTES];
    char* buffer = NULL;
    unsigned long long clen;
    unsigned char* plaintext2 = NULL;

    std::ifstream plaintextfile(original, std::ifstream::binary);
    if (plaintextfile) {
        // get length of file:
        plaintextfile.seekg(0, plaintextfile.end);
        clen = plaintextfile.tellg();
        plaintextfile.seekg(0, plaintextfile.beg);

        buffer = new char[clen];
        ciphertext = new unsigned char[clen];
        plaintext2 = new unsigned char[clen];

        plaintextfile.read(buffer, clen);

        plaintextfile.close();
        std::cout << std::endl;
    }
    std::cout << "---" << std::endl;
    plaintext = (unsigned char*)buffer;
    for (int i = 0; i < clen; i++)
        std::cout << plaintext[i];
    std::cout << std::endl;
    std::cout << "---" << std::endl;

    randombytes_buf(nonce, sizeof(nonce));
    randombytes_buf(key, sizeof(key));

    int result = crypto_stream_chacha20_xor_ic(ciphertext, plaintext, clen, nonce, 0, key);
    int result2 = crypto_stream_chacha20_xor_ic(plaintext2, ciphertext, clen, nonce, 0, key);
    for (int i = 0; i < clen; i++)
        std::cout << (unsigned int)ciphertext[i];
    std::cout << std::endl;
    std::cout << "---" << std::endl;
    for (int i = 0; i < clen; i++)
        std::cout << plaintext2[i];
    std::cout << std::endl;
    std::cout << "---" << std::endl;
    std::cout << "Error Enc = " << result << std::endl;
    std::cout << "Error Dec = " << result2 << std::endl;

    FILE* encryptFile;
    encryptFile = fopen(destiny, "w");
    if (encryptFile != NULL) {
        fputs(reinterpret_cast <const char*> (ciphertext), encryptFile);
        fclose(encryptFile);
    }
    else {
        return 1;
    }

    delete[] plaintext2;
    delete[] ciphertext;
    delete[] buffer;

    return 0;
}

int extractSecret(const char* file, unsigned char key[crypto_stream_chacha20_KEYBYTES]) {
    string data;
    data = readFileIntoString(file);

    std::copy(data.begin(), data.end(), key);
    key[data.length()] = 0;

    return 0;
}

int extractPublic(const char* file, unsigned char publicKey[crypto_sign_PUBLICKEYBYTES]) {
    string file_contents;
    file_contents = readFileIntoString(file);

    std::copy(file_contents.begin(), file_contents.end(), publicKey);
    publicKey[file_contents.length()] = 0;

    return 0;
}

int extractPrivate(const char* file, unsigned char privateKey[crypto_sign_SECRETKEYBYTES]) {
    string file_contents;
    file_contents = readFileIntoString(file);

    std::copy(file_contents.begin(), file_contents.end(), privateKey);
    privateKey[file_contents.length()] = 0;

    return 0;
}

int writeSecret(const char* file, const unsigned char key[crypto_stream_chacha20_KEYBYTES]) {
    FILE* keyFile;
    keyFile = fopen(file, "w");
    if (keyFile != NULL) {
        fputs(reinterpret_cast < const char* > (key), keyFile);
        fclose(keyFile);
    }
    else {
        return 1;
    }
    return 0;
}

int writeKeys(const char* publicFile, const char* privateFile, const unsigned char publicKey[crypto_sign_PUBLICKEYBYTES], const unsigned char privateKey[crypto_sign_SECRETKEYBYTES]) {
    FILE* publicKeyFile;
    publicKeyFile = fopen(publicFile, "w");
    if (publicKeyFile != NULL) {
        fputs(reinterpret_cast < const char* > (publicKey), publicKeyFile);
        fclose(publicKeyFile);
    }
    else {
        return 1;
    }

    FILE* privateKeyFile;
    privateKeyFile = fopen(privateFile, "w");
    if (privateKeyFile != NULL) {
        fputs(reinterpret_cast < const char* > (privateKey), privateKeyFile);
        fclose(privateKeyFile);
    }
    else {
        return 1;
    }
    return 0;
}

int showMenu() {
    cout << "Proyecto Software de Proteccion de Documentos - Miguel Valle\n";
    cout << "------------------------------------------------------------\n";
    cout << "\n";
    cout << "Las operaciones disponibles son las siguentes:\n";
    cout << "1. Generacion de Claves\n";
    cout << "2. Recuperacion de Claves\n";
    cout << "3. Cifrado y Descifrado de Archivos\n";
    cout << "4. Firma de Archivos\n";
    cout << "5. Verificacion de Firma de Archivos\n";
    cout << "\n";

    //select a function
    int op;
    cout << "Ingresa que operacion deseas ejecutar: ";
    cin >> op;
    cout << "Operacion seleccionada: " << op;
    cout << "\n\n";
    return op;
}

int main() {
    int work = 1;

    if (sodium_init() == -1) {
        return 1;
    }

    //Se declara la llave secreta para cifrar/descifrar
    unsigned char secretKey[crypto_stream_chacha20_KEYBYTES];

    crypto_secretstream_xchacha20poly1305_keygen(secretKey);

    //Se declara la llave pública
    unsigned char publicKey[crypto_sign_PUBLICKEYBYTES];

    //Se declara la llave privada 
    unsigned char privateKey[crypto_sign_SECRETKEYBYTES];

    //Se guarda el par de llaves
    crypto_sign_keypair(publicKey, privateKey);

    string a, b, c;
    char origin[512], destiny[512];

    while(work) {
        //show menu and select a function
        int op = showMenu();

        //operation
        if(op == 1) {
            cout << "GENERACION DE CLAVES\n";
            cout << "--------------------\n\n";
            cout << "Escriba la ruta donde se guardara la llave secreta: ";
            cin >> a;
            strcpy(origin, a.c_str());
            if (writeSecret(origin, secretKey) != 0) {
                return 1;
            }
            cout << "Escriba la direccion donde se guardara la llave publica: ";
            cin >> a;
            cout << "Escriba la direccion donde se guardara la llave privada: ";
            cin >> b;
            strcpy(origin, a.c_str());
            strcpy(destiny, b.c_str());
            if (writeKeys(origin, destiny, publicKey, privateKey) != 0) {
                return 1;
            }
        }
        else if(op == 2) {
            int temp = 1;
            while (temp) {
                cout << "RECUPERACION DE CLAVES\n";
                cout << "----------------------\n";
                cout << "0. Salir\n";
                cout << "1. Extraer llave secreta\n";
                cout << "2. Extraer una llave publica\n";
                cout << "3. Extraer una llave privada\n";
                cout << "Ingresa tu eleccion: ";
                cin >> temp;
                if (temp == 0) {
                    break;
                }
                else if (temp == 1) {
                    cout << "Escriba la ruta donde se guarda la llave secreta: ";
                    cin >> a;
                    strcpy(origin, a.c_str());
                    if (extractSecret(origin, secretKey) != 0) {
                        return 1;
                    }
                }
                else if (temp == 2) {
                    cout << "Escriba la direccion donde se guarda la llave publica: ";
                    cin >> a;
                    strcpy(origin, a.c_str());
                    if (extractPublic(origin, publicKey) != 0) {
                        return 1;
                    }
                }
                else if (temp == 3) {
                    cout << "Escriba la direccion donde se guarda la llave privada: ";
                    cin >> b;
                    strcpy(destiny, b.c_str());
                    if (extractPrivate(destiny, privateKey) != 0) {
                        return 1;
                    }
                }
            }
        }
        else if (op == 3) {
            cout << "Escriba la direccion del archivo a encriptar: ";
            cin >> a;
            cout << "Escriba la direccion del archivo encriptado: ";
            cin >> b;
            strcpy(origin, a.c_str());
            strcpy(destiny, b.c_str());
            if (encrypt(origin, destiny, secretKey) != 0) {
                return 1;
            }
            cout << "\n";
        }
        else if (op == 4) {
            cout << "Escriba la direccion del archivo a firmar: ";
            cin >> a;
            cout << "Esciba la direccion del archivo firmado: ";
            cin >> b;
            strcpy(origin, a.c_str());
            strcpy(destiny, b.c_str());
            if (signFile(origin, destiny, publicKey, privateKey) != 0) {
                return 1;
            }
            cout << "\n";
        }
        else if (op == 5) {
            cout << "Escriba la direccion del archivo a verificar: ";
            cin >> a;
            strcpy(origin, a.c_str());
            if (verify(origin, publicKey) != 0) {
                return 1;
            }
            cout << "\n";
        }

        //ask if wanna do another operation
        cout << "Deseas hacer otra operacion? (0 = NO || 1 = SI): ";
        cin >> work;
        cout << "\n\n";
    }

    cout << "GRACIAS, VUELVA PRONTO!\n";

	return 0;
}
