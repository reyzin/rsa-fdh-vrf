/**
 !!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!
 THIS CODE IS INSECURE AND NOT TO BE USED FOR ACTUAL CRYPTO!!!
 IT IS ALSO INEFFICIENT AND COBBLED TOGETHER JUST TO GET IT WORKING!!! DO NOT USE IT!!!
 It was written by Leo Reyzin as a reference implementation only, in order to
 generate test vectors for https://github.com/cfrg/draft-irtf-cfrg-vrf
 */

/*
This is free and unencumbered software released into the public domain.

Anyone is free to copy, modify, publish, use, compile, sell, or
distribute this software, either in source code form or as a compiled
binary, for any purpose, commercial or non-commercial, and by any
means.

In jurisdictions that recognize copyright laws, the author or authors
of this software dedicate any and all copyright interest in the
software to the public domain. We make this dedication for the benefit
of the public at large and to the detriment of our heirs and
successors. We intend this dedication to be an overt act of
relinquishment in perpetuity of all present and future rights to this
software under copyright law.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

For more information, please refer to <http://unlicense.org>
 */

/**
 !!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!
 THIS CODE IS INSECURE AND NOT TO BE USED FOR ACTUAL CRYPTO!!!
 IT IS ALSO INEFFICIENT AND COBBLED TOGETHER JUST TO GET IT WORKING!!! DO NOT USE IT!!!
 It was written by Leo Reyzin as a reference implementation only, in order to generate test vectors.
 */

#include <NTL/ZZ.h>
#include "sha512.h"
#include "sha256.h"

NTL_CLIENT

unsigned char hexToNum(unsigned char in) {
    if ('0'<=in && in<='9') return in-'0';
    return in-'a'+10;
    
}
unsigned char numToHex(unsigned char in, bool upperCase) {
    if (in<10) return in+'0';
    return in-10 + (upperCase ? 'A' : 'a');
}


void printArray(const unsigned char *  input, int iLen) {
    for (int i = 0; i<iLen; i++) {
        printf("%02x", input[i]);
    }
}

enum Hash {SHA256, SHA384, SHA512};
struct cipherSuite {
    Hash h;
    int hLen;
    unsigned char suite_string;
};
cipherSuite RSA_FDH_VRF_SHA256 = {SHA256, 32, '\1'};
cipherSuite RSA_FDH_VRF_SHA384 = {SHA384, 48, '\2'};
cipherSuite RSA_FDH_VRF_SHA512 = {SHA512, 64, '\3'};

struct key {ZZ p; ZZ q; ZZ n; ZZ d; ZZ e;};

class str {
public:
    unsigned char * s;
    int len;
    
    // NOTE: REQUIRES SOURCE AND DESTINATION TO BE NONOVERLAPPING
    static void reverse (unsigned char * dest, unsigned char * source, int len) {
        if ((dest<=source && dest+len>source) || (source<=dest && source+len>dest) ) {
            cout<<"CAN'T USE REVERSE WITH OVERLAPPING SOURCE AND DESTINATION\n";
            exit(-1);
        }
        for (int i = 0; i<len; i++){
            dest[i] = source[len-1-i];
        }
    }
    

    // From hex string
    str(const char *  input) {
        len = strlen(input)/2;
        s = new unsigned char[len];
        for (int i = 0; i<strlen(input); i+=2) {
            s[i/2] = hexToNum(input[i])*16+hexToNum(input[i+1]);
        }
    }

    // From C string -- a factory constructor
    static str fromCString(const char * input) {
        str ret;
        ret.len = strlen(input);
        ret.s = new unsigned char[ret.len];
        for(int i=0; i<ret.len; i++) ret.s[i] = input[i];
        return ret;
    }

    // From a single octet
    str(unsigned char c) {
        len = 1;
        s = new unsigned char[len];
        s[0]=c;
    }
    
    // From a single octet, repeated num times
    str(unsigned char c, int num) {
        len = num;
        s = new unsigned char[len];
        for (int i=0; i<len; i++) {
            s[i]=c;
        }
    }

    // from a big int -- big-endian
    str(const ZZ & n, int nlen) {
        len = nlen;
        unsigned char * r = new unsigned char[len];
        BytesFromZZ(r, n, nlen);
        s = new unsigned char[len];
        reverse(s, r, len);
        delete [] r;
    }

    // from str -- slice
    str slice(int begin, int end) const {
        if (! (0<=begin && begin<=end && end<=len)) {
            cout<<"ERROR -- SLICE BEGIN OR END OUT OF BOUNDS\n";
            exit(-1);
        }
        str ret;
        ret.len = end-begin;
        ret.s = new unsigned char[ret.len];
        memcpy(ret.s, this->s+begin, ret.len);
        return ret;
    }
    
    str strxor(const str & that) const {
        if (len != that.len) {
            cout<<"ERROR -- XOR APPLIED TO STRINGS OF DIFFERENT LENGTHS\n";
            exit(-1);
        }

        str ret;
        ret.len = len;
        ret.s = new unsigned char[len];
        for (int i=0; i<len; i++) {
            ret.s[i] = s[i]^that.s[i];
        }
        return ret;
    }

    
    str hash_sha512() const {
        str ret;
        ret.len = 64;
        ret.s = new unsigned char[ret.len];
        mbedtls_sha512_ret(s, len, ret.s, 0);
        return ret;
    }

    str hash_sha384() const {
        str ret;
        ret.len =  48;
        ret.s = new unsigned char[ret.len];
        unsigned char * temp = new unsigned char[64];
        mbedtls_sha512_ret(s, len, temp, 1);
        memcpy(ret.s, temp, 48);
        return ret;
    }
    
    str hash_sha256() const {
        str ret;
        ret.len = 32;
        ret.s = new unsigned char[ret.len];
        SHA256_CTX ctx;
        sha256_init(&ctx);
        sha256_update(&ctx, s, len);
        sha256_final(&ctx, ret.s);
        return ret;
    }
    
    str hash(Hash h) const {
        switch (h) {
            case SHA256:
                return hash_sha256();
            case SHA384:
                return hash_sha384();
            case SHA512:
                return hash_sha512();
            default:
                cout<< "ERROR -- UNKNOWN HASH ID" << endl;
                exit(-1);
        };
    }


    // empty
    str() {
        s = NULL;
        len = 0;
    }

    str (const str& that) {
        len = that.len;
        s = new unsigned char [len];
        memcpy(s, that.s, len);
    }
    
    str & operator=(const str& that) {
        if (s!=NULL) {
            delete []s;
        }
        len = that.len;
        s = new unsigned char [len];
        memcpy(s, that.s, len);
        return *this;
    }
    
    ~str () {
        if (s!=NULL) {
            delete[] s;
        }
    }
    
    // concatenate
    str operator||(const str & that) const {
        str ret;
        ret.len = this->len+that.len;
        ret.s = new unsigned char[ret.len];
        memcpy(ret.s, this->s, this->len);
        memcpy(ret.s+this->len, that.s, that.len);
        return ret;
        
    }
    
    // concatenate with a single character
    str operator||(char c) const {
        str ret;
        ret.len = this->len+1;
        ret.s = new unsigned char[ret.len];
        memcpy(ret.s, this->s, this->len);
        ret.s[len]=c;
        return ret;
    }

    
    // to hex string (lowercase)
    char * toHexString() const {
        char * ret = new char[len*2+1];
        for (int i = 0; i<len; i++) {
            ret[2*i] = numToHex(s[i]/16, false);
            ret[2*i+1] = numToHex(s[i]%16, false);
        }
        ret[2*len] ='\0';
        return ret;
    }
    
    // to integer -- big-endian
    ZZ toZZ() const {
        unsigned char * r = new unsigned char [len];
        reverse (r, s, len);
        ZZ ret;
        ZZFromBytes(ret, r, len);
        delete [] r;
        return ret;
    }

    bool operator == (const str & that) const {
        if (len != that.len) return false;
        return !memcmp(s, that.s, len);
    }
    bool operator != (const str & that) const {
        return ! (*this==that);
    }

    // case insensitive
    bool operator == (const char * hexString) const {
        char * temp = this->toHexString();
        int i;
        for (i = 0; temp[i]!='\0' && hexString[i]!='\0'; i++) {
            if (tolower(temp[i])!=tolower(hexString[i])) return false;
        }
        return temp[i]==hexString[i];
    }
    bool operator != (const char * hexString) const {
        return ! (*this==hexString);
    }
    
};

ostream& operator<<(ostream& os, const str& s)
{
    os << s.toHexString();
    return os;
}

// See Appendix B.2.1 of RFC 8017 https://www.rfc-editor.org/info/rfc8017
str MGF1(const str & mgfSeed, int maskLen, const cipherSuite & cs) {
    int hLen;
    
    int n = (maskLen-1)/cs.hLen; // this gives floor of (maskLen-1)/hLen, which is equal to ceil of maskLen/hLen - 1
    str T;
    for (ZZ counter(0); counter <= n; counter++) {
        T = T || (mgfSeed || str(counter, 4)).hash(cs.h);
    }
    return T.slice(0, maskLen);
}

str RSAFDHVRF_ProofToHash(const str & pi_string, const cipherSuite & cs) {
    str proof_to_hash_domain_separator('\2');
    return (str(cs.suite_string) || proof_to_hash_domain_separator || pi_string).hash(cs.h);
}

str RSAFDHVRF_Prove(const ZZ & n, const ZZ & d, const str & alpha_string, const cipherSuite & cs, bool verbose) {
    int k = (int)NumBytes(n);
    str mgf_domain_separator('\1');
    str MGF_salt = str(ZZ(k), 4) || str(n, k);
    
    str EM = MGF1(str(cs.suite_string) || mgf_domain_separator || MGF_salt || alpha_string, k-1, cs);
    if (verbose) cout << "          <li>EM = " << EM << "</li>" << endl;
    
    ZZ m = EM.toZZ();

    // RSASP1
    ZZ s = PowerMod(m, d, n);
    
    str pi_string(s, k);
    if (verbose) cout << "          <li>pi = " << pi_string << "</li>" << endl;
    
    // beta
    if (verbose) cout << "          <li>beta = " << RSAFDHVRF_ProofToHash(pi_string, cs) << "</li>" << endl;

    return pi_string;
}


bool RSAFDHVRF_Verify(const ZZ & n, const ZZ & e, const str & alpha_string, const str & pi_string, const cipherSuite & cs) {
    ZZ s = pi_string.toZZ();
    
    // RSAVP1
    if (s<0 || s>=n) return false;
    ZZ m = PowerMod(s, e, n);
    
    int k = (int)NumBytes(n);
    str mgf_domain_separator('\1');
    str MGF_salt = str(ZZ(k), 4) || str(n, k);
    
    str EMPrime = MGF1(str(cs.suite_string) || mgf_domain_separator || MGF_salt || alpha_string, k-1, cs);
    ZZ mPrime = EMPrime.toZZ();
    return m==mPrime;

}

bool testSHA256 (){
    // these test vectors are from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
    str msg [] = {
        "",
        "d3",
        "5a86b737eaea8ee976a0a24da63e7ed7eefad18a101c1211e2b3650c5187c2a8a650547208251f6d4237e661c7bf4c77f335390394c37fa1a9f9be836ac28509",
        "e5098b6a0b1cfc57c6a76537104a39c48baecb15c6bbb46fbb0b745f9c9e5c05cfcfabb33786f7b7b5b0ce74eeec9eb84f87d2494fab3ec1f4d3bd9c99821890ee352a1d40964264fbf2c93c6ded2583cc75dcb27bf4fdb489cabcf97bfa5cc64b2352cfb0b3a707a0579eb713b697cd0b5e3377d1feb9f181d7b89cc86dee4fed8269f10e44ec48adc6940c6badbb40122c1dc2d9323920e4e1fbad0b4397d4dc38b8ade3b3dace2926f464fa3b5b82ebc5e3b81cf647e8bbd2cb55c9e31ffd212f8729b66739421c6106e64ac83d3b9e13cd8321b3a9f10d9171bb8cb74e71c34d1e8d0fc8d14b8e5e12bbe2bd2a1431fc224b70d228e4e2063509db26ecd9ca7cc402763e69928805600a4a80eab4ae6a2c3792b98c6942195e643f98c0dc3fa3c2b07431cbbe113e38fc0b7b45c51c4431700ed29d2736b236f63f75932329aa60be9009bd7832f1e1b9ac1503ec84727a1e6c8423c7c5b903e763262d559078e654532e0868f206a468b5b5ebd3eddb4f673536e5f0f8160e5f3311561b7cf79c9c440974355965c931aec5c7225f69f776f052ac4bd6b19f85389fd61df60ecabbeb00c8886ff7983d20ac5d81e303bc71253f40806772fd81f938740205a5b7dcd07cce083da258b493d275967f91e4815d656936b342727cfe45f973b2a5ac257ce64c5eca4f53be8d9fd90c3dfcb8cd1e2cef15c307449ed02c2e1704f4f1be76a40b311ee7cf81987b5089252a807ef3fc99c79eabbc0ef657d897037bced04620d32a425015283bcea1b53e0484bb613d30f14c1422f5f82cc29ab7228b8375c06bf13d746dd9ff00953a90720badf2577d3ed62cbe7a5f15b3c929d26ffe8aee9d2d17391ebc6a79f4bd235d5f7b2db2455343d9d7c6b27972cc6071c36a0d112f86d98972fb06a186e900abc64e9ab653db9b05b70079c0c84a64e8cfee8690eaa68a4bafbb5be112632e46894ec2cc6e7ce697a4513d517deb3e20dbb37ed5963232671e27ef9f62d6b514f0a22c5a5dde2d77e7e184965958f5002fe17d47fbd5d9c407644d443ce89eff427360cae9aa788dc8d7d9f62439916f139f094ee035884cb29dfa396941f0eec9e8e782da88cdc18e5bc1d9a5351b57ce15ac520ffa47e666f87fe5b18ab3c8cb2a48ecf81f36fb8397c6a7a5f59a9fa96cedbb4ecd1c7a6d9d65afdb6bef7791600b6e0a18ba23edb06fc9ec21162feccc54f2665611f10db53401b18bade263b3b972da1a612115d144a5426097efdf5c6a5d1f3c2d318f687242f993f5f1884bd95f2ece34dd4320cea46f5a26c7c945b665402778233bdda9d97c2acd8c4a4ff39dcfdc3a3fbfc5942e3ab8ca9ff4aec17293c1fbaf583d603002f93f9befe8909485eb7c30d0e91fac6c228c5fa6c011eddeafbdbe30af20ae53a85206c03d37ac17a30096bfb4f584cd3f72ef28a3303cea9cc636095c70bb36de0eb50577704d4faed05bd54da020"
    };
    str res[] = {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1",
        "42e61e174fbb3897d6dd6cef3dd2802fe67b331953b06114a65c772859dfc1aa",
        "3380c8dae5c0b68bb264b757e2451c21cbe2b899fe7a871ab1bae6041f48e7ad"
    };
    for (int i=0; i<4; i++) {
        if (msg[i].hash_sha256() != res[i]) {
            cout << "ERROR IN SHA 256 Test" << endl;
            return false;
        }
    }
    return true;
}

bool testSHA384 (){
    // these test vectors are from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
    str msg [] = {
        "",
        "c5",
        "3bf52cc5ee86b9a0190f390a5c0366a560b557000dbe5115fd9ee11630a62769011575f15881198f227876e8fe685a6939bc8b89fd48a34ec5e71e131462b2886794dffa68ccc6d564733e67ffef25e627c6f4b5460796e3bce67bf58ca6e8e555bc916a8531697ac948b90dc8616f25101db90b50c3d3dbc9e21e42ff387187",
        "f6b1cf75b5cfa4ab323cf04ff13b7a591b23d06ed25f3c04c1baf4c8f7da913cf509c2a5053c4224ce4d0723268cbdf2277672b285c493731ea81799d353fa8497baed70c59a4c99b7b950a39470863a69667ff67c9ec981ddb41ffb3d63dd9d034bb79d9df1a95214083199e4efbd770a7a5f005ef5c877236674b6dd1322d0624487f6344a43970ec014cbbd114af2313b7b98d4d2779d1b477e925a6ab165dc2ec74133ac01b0cd6b6003c8df15f3072f3988863cbe3aeadea6575d7072a49890de474120cbe478907d07ad6006c2b4e002971b3b8597bbb352cc8d2e4ed5bff234d007ad897d38b8d39f139c06a65fd63f8c3cd7b4fdb44febba93ab2b3f78dc31a42d5b23c1346aca95a29cfbe931975630901934b2fd39dae916f0f32becd73d8a5a3282f9952ecab00367cfd151adb14bc008ebfebff98621bf038ce1436ac04b363b8c6c828c3bb7de0568a7e7a0b6a573acc22b2218562a36eee0a9a41e22af6a7d2a64240d8573da7fb0b21df6cf05520ea1804d1db4cb22b9d5cb377acb7e9e004527a23810aca0dc8d3c1939633404357144699007ce2b6a558e2606238079cdc3fe25964429d824e98b03f0d9fb322918c09dfab6f9fa0b473c964a937da4eb8e31d5ad8ab42960abe804a49b2084f3803c12e22b1537a3921bb1cf813cc7628c08d90848133b97bb9b44dc106ba19a8fffefd0cde98a3b20749f1c5686893ba7cb5a2ce70fb7d101ecea20a0a632262f535d4c043f99dad88e88b97b23927dc5c17fa3d070451664231ef8b397dea0477e84df38dd0f88a2b3932f56db8b30d03371f46afe8c6fcf870aedb1084e0fbfc98b10d18c924d6629e80551761c5daf6957a71c8135e32761d38603bf2a7b7f7c9b683714ca320c39b0c3d3bbec0b4aab5a4450c0e77b55f9a44c0f8419ed6edfdb6ed33d613e7d2b13f24373a4428941a2546d844b3e4197a3c63e21c36b763a74aa0bcffc7a9f4738190b66eb0a5472565fdb950934d383f87cf85cd1007ed48da4489146ec5bd548c0925c6a6c93889feb01bbc865f404ccf6a6ffebb16ff64fe5f34ce49e9a1c6a6f401dc96f2ec9a48249be30da8a6447bdaed0b8882fe8e2f472c881984265c7af7d70af1c0d7e8eab1a65ea9a7ee990587a98e18ca7f26d592fcdc3e03cf88607b11fc47919ee84efdc799eadb9dcd04f701e0dc5bf5c189d90235280711dd10044f0b1913863afd4f8c3f31c22852e2bfa2ce53c606d0d47ff91d780c81ccd209fac1e69532336e4d40892eea02bd3727f8811f8706e71dfe3e1fae6283ca4f2281bb20b537742a7d913232b1d17e6af67fb3801d8a76feda4d962bc7bc67efb4804167e1ea7fba46fab4ddb80929067194d026081602cfaaa42b80aa80282c56730f2ca9efb8863ff97b807b1e2f924ff46191c52e1d38d5c"
    };
    str res[] = {
        "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        "b52b72da75d0666379e20f9b4a79c33a329a01f06a2fb7865c9062a28c1de860ba432edfd86b4cb1cb8a75b46076e3b1",
        "12b6cb35eda92ee37356ddee77781a17b3d90e563824a984faffc6fdd1693bd7626039635563cfc3b9a2b00f9c65eefd",
        "70a597d1f470d69d7b7d495531c3182704dd60db5c73429fd7108c8ee22d86ed5822adfe6352f28f93023f46cc8d60bb"
    };
    for (int i=0; i<4; i++) {
        if (msg[i].hash_sha384() != res[i]) {
            cout << "ERROR IN SHA 384 Test" << endl;
            return false;
        }
    }
    return true;
}


bool testSHA512 (){
    // these test vectors are from https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing
    str msg [] = {
        "",
        "21",
        "fd2203e467574e834ab07c9097ae164532f24be1eb5d88f1af7748ceff0d2c67a21f4e4097f9d3bb4e9fbf97186e0db6db0100230a52b453d421f8ab9c9a6043aa3295ea20d2f06a2f37470d8a99075f1b8a8336f6228cf08b5942fc1fb4299c7d2480e8e82bce175540bdfad7752bc95b577f229515394f3ae5cec870a4b2f8",
        "afdccc84f257cb768b7ad735edbd1990b6114bad876928ab1279208574bd513ac6beb32bee9192c4bba0425e32ad0e64221371b5ff4f894aecc0c8191aabed3951823246cc66c7074aea804e621acb2017bce416acd54c03ba6f77d77f9ac4c479b1b39f33de538860e0f9cd260c370cbc920c983702591ea10f94894c92c02265d29dfccc021c8f230b15a3268c3c703a1f520348df98e3cb2789f5289cc89d3f6d58263fd90b64bef23d9709a1c193b8eb1c1e8672f19a603fbde4bcbec57b2c0a4ce5336b084e571ed7737754afbe5f7cd3b29ac54d8a87df981db0029d055632e10051c1fc9617154dfd1aacec39575ce0872be092fc6990826aab703983e56c7f4140e2cd85256105fe97b1614cc713a965e2c9aa382ed9e391550f813d01418e6ea8d66561aa89693d996bf63fd7279814678a7b86fd43235b57e75d7ad038765033a6aa72cd16df84c6e39459b122145b612bef2efe55aa905900b6847dd99faf87598602b78fd199c62021e37a8c840479b2ed775b97e1f8026372a12eac71534cf7e0578f7ca645422a86255deb52d556295cab39912e5afb177b1a0c3a55032b899fba7e66c650e20aac6780c9e597a1972610c3ccfa80eb24b7373e0ab189cb16ad73acd499824dc77af10bada511010532ee1ecfae307b93103feca4eeabd6a6f1ca404e87a32c69d70a2720fa0d1f7a688f7522b033536b6d7c40917532f1425307625cf87a26f9adfcfca94c51a2feb03aee4e6a511ab4b5346058ade5c6f0bb713c8754d0e47de30db1d003a73399f236b1da42517976d2b07481fd8efdba1151f356036d0d0061866e1d87d57a5416cce74ea2fd17baab38a595cff33ea83defb2526d194a870faf5d1941a31e360444b833f11b9d8728131a1b8ade30c128939f01fa9c431cd5cfa34b97dbc848a5e64b0f9774b2e6318bfd9b95157b0db885e2ed13bd9fc69b2f6b3bf2431f91dff9c96dfcd0ffdeaee6739d5a60c894d60ca49e1e45078e4918db72bba5cc199bc759d288f72b77876da6aa4089bf5f6b720d9b85fd227ac7d01b7758c776e8c29624c8a3b0dfb9a568be49af5607755dfd446caeaa9995fd9f54d23371c6073aaf52d6b5c4c3adee1fe2030f9149de96f67299031713e4d3cfae0cb26d637ded5a0a8526fc7e5a4bd93b5fc9002ca3fca5beaaea0b397132a750ac3f82f752c1df745b5e1eb9c9a4e0f1e5436c59cb79515128cd4db343006e633a4177278ea085b9e2c5f21b00e27a2b1de69c775ef443529b13a62862276d0e3f20159d3a719501a2c3424d09ebf011901a5a2f6554c4ea8924de40d78dec7a424324015e1c577322c1d4f6eca98acdc5486c29e6831a417c68bda4a91c32cecb146cfa00881338ea2571bfaf038f8444d69b0cec688d7efb470bfce0ba893362fab4312a9f11778259"
    };
    str res[] = {
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        "3831a6a6155e509dee59a7f451eb35324d8f8f2df6e3708894740f98fdee23889f4de5adb0c5010dfb555cda77c8ab5dc902094c52de3278f35a75ebc25f093a",
        "a21b1077d52b27ac545af63b32746c6e3c51cb0cb9f281eb9f3580a6d4996d5c9917d2a6e484627a9d5a06fa1b25327a9d710e027387fc3e07d7c4d14c6086cc",
        "014fd2fa6b05c4fca1a5c0753f15c940b5f976b41a40bf6bb14afe839d83a4676173940717bb7e746a2ac77f573e6744cf0002b78b5b7f664e22434e22d0ccd0"
    };
    for (int i=0; i<4; i++) {
        if (msg[i].hash_sha512() != res[i]) {
            cout << "ERROR IN SHA 512 Test" << endl;
            return false;
        }
    }
    return true;
}



bool testMGF1()
{
    /* These test vectors for MGF1 were created manually using the online SHA calculator at https://emn178.github.io/online-tools/sha256.html */
    str mgfSeed = str("deadbeef");
    str MGF1SHA256MaxOutput =  str ("a49eea4c082081ca8e405f9e8c880f57de8f7e2a121eabd1e2815c233b22e4538cc20abb816f996a86b3c5a3bf047e8c4eab43a7158434aa5e57c28576f2e04cd3e83885d191ce6fddaff08622befb66ea1b2b2ed092a90551d873303717cb605491a9ba17d6692cc489c606ac2429b69ac02a5cf350514df6b7d0858bab80ec");
    
    for (int i = 0; i<=MGF1SHA256MaxOutput.len; i++) {
        if (MGF1(mgfSeed, i, RSA_FDH_VRF_SHA256)!=MGF1SHA256MaxOutput.slice(0, i)) {
            cout << "ERROR MGF1 SHA256 output; length " << i << endl;
            return false;
        }
    }

    str MGF1SHA384MaxOutput =  str ("1d811399ad575afa5835154f773df112a8e571efe99998b454f7352f3bc8db7875c0412598bd6c72a646b2602fdf3bd79cbd76e0a3cbe94ede249e1aa3ad779338cf89353ab12c8842303ba13f71902ed707fc139bad91591e89521c12b8d02a92e4b70b227c8258c22be3bcacd79f65204e75f48a5a0c27629126e0d2ce9dd4b485ed19a4ff87d7a148082c0f293b2be950e50691225a104d5aa1f3f21c72bd5eb93ad78e5a9f931a9de5fe0620139d041cb62746b1ee85412d06bfaf2b8cff");

    for (int i = 0; i<=MGF1SHA384MaxOutput.len; i++) {
        if (MGF1(mgfSeed, i, RSA_FDH_VRF_SHA384) != MGF1SHA384MaxOutput.slice(0, i)) {
            cout << "ERROR MGF1 SHA384 output; length " << i << endl;
            return false;
        }
    }

    str MGF1SHA512MaxOutput =  str ("60d84c125a67aa2bd748ff356d054ba992c8004395f4f1d1d51e2011360ee4248b4e22956e9b8a19f8ca80aefa3138db9d09b3cd25d975d65865259ea8d69e1f26b5c693f61289b8a2d6128f38e490442a1c6e5154ad2d64cb6369fb78eec8b9ce3520d330f9d1b88ec8cfaf8295988e291702cd5b69b155518ad5e5aedae258f2e3f66d79d27271220c30bafcb07f0c952183f016a74b4e1e67a27251459c0c4985a4f231843957fcccb804af6a07d9340c9df0636a560a0e9e0cb5639211413d08c7ca253dffe391e90004140e09b040fffdc42c640cda09d00625fb59e29832412703cc667c1de24fb81ac10c815896278d47db42314631b4777189b5ce70");

   for (int i = 0; i<=MGF1SHA512MaxOutput.len; i++) {
        if (MGF1(mgfSeed, i, RSA_FDH_VRF_SHA512) != MGF1SHA512MaxOutput.slice(0, i)) {
            cout << "ERROR MGF1 SHA512 output; length " << i << endl;
            return false;
        }
    }

    return true;

}

bool testVRFExample(const ZZ & n, const ZZ & d, const ZZ & e, const char * alpha_input, const str & pi_string, const str & beta_string, const cipherSuite & cs) {
    str alpha(alpha_input);
    
    str ret = RSAFDHVRF_Prove(n, d, alpha, cs, false);
    if (ret != pi_string) {
        cout << "ERROR VRF Example Test Wrong Proof" << endl;
        return false;
    }
    
    if (RSAFDHVRF_ProofToHash(pi_string, cs) != beta_string) {
        cout << "ERROR VRF Example Test Wrong Beta" << endl;
        return false;
    }
    
    if (!RSAFDHVRF_Verify(n, e, alpha, ret, cs)) {
        cout << "ERROR VRF Example Does Not Verify" << endl;
        return false;
    }
    return true;
    
}

void generateTestVector(const ZZ & n, const ZZ & d, const ZZ & e, const char * alpha_input, const cipherSuite & cs) {
    cout << "        <ul empty=\"true\" spacing=\"compact\">"<<endl;
    
    str alpha(alpha_input);
    cout << "          <li>alpha = " << alpha ;
    if(alpha.len == 0) cout << " (the empty string";
    else if(alpha.len == 1) cout << " (1 byte";
    else cout << " (" << alpha.len << " bytes";
    if (alpha.len > 0) {
        cout << "; ASCII \"";
        for (int i=0; i<alpha.len; i++) cout<< alpha.s[i];
        cout <<"\"";
    }
    cout <<")</li>" << endl;
    
    RSAFDHVRF_Prove(n, d, alpha, cs, true);
    cout<<"        </ul>"<<endl;
}

bool testKey(const key & k) {
    bool ret = (k.p*k.q == k.n && (k.e*k.d)%(k.p-1)==1 && (k.e*k.d)%(k.q-1)==1);
    if (not ret) cout << "ERROR: PK does not match SK";
    return ret;
}

key key2048, key3072, key4096;

bool vrfExampleTests() {
    // These test vectors were provided by Malte Thomsen, Marcus Rasmussen, and Tobias Vestergaard, generated using their code at https://github.com/hacspec/hacspec/blob/master/examples/rsa-fdh-vrf/src/rsa-fdh-vrf.rs
    
    bool test = true;
    
    ZZ n1 = str ("64f70acdc41c0ee7cb4961760368e34889c058ad3c7e578e8e72ed0d2fd1c7cfbb8beffd107204d544919db9d2470669c969e178d4deb8393daec4584ca9f162805c9ba46e617d89d4ab6480b0873b1cb92cf7232c88f013931ffe30f8ddf2cddbff4402bcb721985d2bb2eee5382dd09210b5d1da6b6b8207fe3e526de54efb55b56cd52d97cd77df6315569d5b59823c85ad99c57ad2959ec7d12cdf0c3e66cc57eaa1e644da9b0ca69b0df43945b0bd88ac66903ec98fe0e770b683ca7a332e69cba9229115a5295273aeeb4af2662063a312cbb4b871323f71888fd39557a5f4610ea7a590b021d43e5a89b69de68c728ce147f2743e0b97a5b3eb0d6ab1").toZZ();
    ZZ d1 = str ("39134e9033a488e8900ad3859b37d804519ae2864c04400ade8c2965a2fabc31ba9bc8f70e2ce67e895ca8053bd1dad6427e106ff626518e4a4859c670d0411ca5e3b438a80d84a23e0f05a99a2158514c7d16d8537cb5fadad8e3215c0e5c0bf3a9c210aa0dfc77dd73ae9b4e090c1d33f52e538b5dde508ba43626f2e906546773ba7401aa6b68ab1151da528336ddafc9a6f2995d89ec282bc555fe41e776216576c0aafb66ef00b718e6c62afd51faf82e7b5a1d430591465b2188fa286ce778eb6a1b346b58331c7820b4142fb808e59ec910aa9b6d340dea673ae7be2d9e1fa91494e40372bcfb92da5fe236dc93b30b0a59b20af8edf3a10e3ea6dfe1").toZZ();
    ZZ e1 = str ("010001").toZZ();
    
    test &= testVRFExample(n1, d1, e1, "", "406581e350c601d6d7518ac928f6753929c56a7480a4a3d011ed65e5f61ca033accd45c03cac2dddcd61b909cedd0df517a1bba4705c9d04a2a8c7d735d24bc3e59b263cc8c18d5f6e2712747d809df7868ac720f90ffd3d7c7b78f3d75f14a9755ea8138804806f4739429d1a313b3abaaf89ce97fbdf10bc01d66723b0b38ad5dc51c87e5f852e2c8fc923cf0f9c86bb7bf8ae808532fcb8a981338d5b13278e66e19915e41c6fbd09f1fce3300da422fbf46f706d1c79f298c740926e14069f83dae52a25bad684e420ad5fc8af3b02e0cf3f79782fb6e7e65abe5e1f6b4fe41f20339b2986fe39f7ce4ceb9c2490d5229e9bfda93150d6800880c411daae", "d065ca3be8716236e99f64139adf481090f0a0c839f86ffda3c4fad948166af0", RSA_FDH_VRF_SHA256);

    test &= testVRFExample(n1, d1, e1, "72", "3d396dc417bee1975ff63c4e8b43b9417be03a91d5eb47309790d74100271342d6dc11511333ec4bc42aea3e02640dc870665044e85085c3dea43eedeb266d9b2de3824aca18b8de3e4d198bde808d80a2a10f0f4bd73fbc7cc36da44cb68af3161b2264e737dcd2d669252abb29f275c971ff6b8234876b7d1ff3d4d05197fe563d6ae92685dccbbbb689b4837da42fe47433019d9bfc50001b11708bf9f656532febf674119c0d67e27714195722fd977e0fc35d7325b5fb3ecb54df53986e01a809d0e5ec442fdacc3d271e7ab5480b8eb18f25cd3baf6a47abc6bf027e8dedef911f2bec367fa5d65e106f314b64cc1d9534d4f26fa034035a43852be66a", "a229210b84f0bb43b296075f226dee433cf2727cd6c2e4871afdeb77414f6a47", RSA_FDH_VRF_SHA256);

    test &= testVRFExample(n1, d1, e1, "af82", "57b07056abc6851330b21ae890fd43ea53b4435319748cf8dba82148ee381c11d21a8660a8714aa59abaac2b7d0141ac4e85b1113b144328eb11461a7f26086896036fc49579a58a2516cecd274946f8dd82fef31652dfe2e2b495966cd6193a1bd197ef6e3472f30bfe14827dd968ea3bf8310dc002a765a0d54b12c3c9627309800b74701a3f7d07a02db0a6ca3a639e60726059727313818a6b671bebe18f078713ced33e50acbfd1e661ec89c5e82b8e1e07f6293f45474aa57d084da46a2437932491d92a87b3393bb0ec62254a3eca19e1004756867839671f84f7a2378097f334832f4aa0442fc5f8637fb2220bb3f2dca247927f0d49ae1c1b2e7455", "ebc5582b6aaf23c424ec1c74e1b8250327c957967fa37566284dac8400e62032", RSA_FDH_VRF_SHA256);

    

    test &= testVRFExample(key2048.n, key2048.d, key2048.e, "", "14234ff8a9487e1b36a23086e258135b8a8a7ff2e23f19c0dfeca0c0a943f119ebd336fdc292ef67b56e32ba06f9941893754a8b97c82f68974b2b34c17f6d43bfd55eb110cd7ea3452d59a24e4ddb8d4cdf040c814e22e3537ca09c2e2dc5dd8ea281e6492ad335378f9f437eed30c51eeeee66ef14efb4000c75c802e9c5a6bb8039c0258d4347981159d0ef6990b5e9c8ac2fb03915d7ff1ffa0626e2e11714a63342e59124c1fcea8e2816c1d9a7751feaaa66cf6c82cd3c58ffde66460d98246ab358cc33baefae4dfb0d191e9b6d6c0e3f92c35200408925dc8bef39b78d1259f8163a5003a693555f05290ef2e68345f27c6e2a8847c5c919d92e7505", "79f0615d4677fb72571889453644013f1a31b08d222e3cee349d64ce1c41045a", RSA_FDH_VRF_SHA256);

    test &= testVRFExample(key2048.n, key2048.d, key2048.e, "", "cffe6067bd9a1285dc1e8e543e8582c1250407cbfbcb2d01c4ddbc0d4ecb5edeb721fb33147cf95f3084f7ce611f9877814770b14b8a671abc7ff085cf5cbe91e72d17f076d62db478d4758412a4e4b77a5591dc32b764a501d27e34e56189ba7347a96f141ed1290f8ef7c4ce4009a9aba0715cbd0148721ea72bce00a22e59460421a21e4d121fc0b4eda62479d93724afae7556abe66326487be38cfb795ac1968c33a3890f2d8c0f7dfbe88bc76f16cbfd2b0f7ee8663abfd7b789caa5f6c77dd1ca991c9a9cc532f7550ad6184c8ece12ca4bea7e67f32405416a1f83245b09d06e7b4214157fb444be12a2eddc4381678f2b862fb240fcedd2da7ffcb3", "dc37e83f8de0e990abada5096a05ca74754cfe7fe8e46b831e24100919415415dcd5a305f5fb8195713cebc78649c8d1", RSA_FDH_VRF_SHA384);

    test &= testVRFExample(key2048.n, key2048.d, key2048.e, "", "a280db108df5ad6ac1bed67efbc5c6fc6da0d301b9c0b41d26e379cd223c613c59d52c987e4baaa6de4de2103284ddd56aa0b662dfe8faa8f6a503b83b7c81f481e23a08761d49a151ada1d9daa132138bbd6f80204c7fa87716b120df957224f92b32a3a0f96c3b209080c408618a92382ab5575f10a57c24ee0ffd01d6b822dc36b27600bf36aafadf0a01e65aa6a0f2fc1a9dcd207d9bf5181a9ca69120e15410800a26efd3ce619349592eeff7b1851737bd033a83f88744ddd3d3e782efb6d2438ffda22ddcaa32c821c6730a05d5bdab88c354809d615884744ff10276496bee70b62feb6ed07a3948823e9ee2a453dbcd4450192c9de0128adfc7e147", "808ca1f8f66a48118aacb011394bd4e5f0011c89ca913943d467b81cc5c43086e588abdde061c3ee30f4c15b2a6b51ad0ada42c0737fd7b2206fb43d35c8ed22", RSA_FDH_VRF_SHA512);

    test &= testVRFExample(key3072.n, key3072.d, key3072.e, "74657374", "69f6042d400dfad4bdb9974fb73d12ec7823c6632df6b0a97ebc14d8a443f74e1eb1a99b37204ba5c7e53bdaf7e3e3fae9efe47cc01d0b061585c8d757ecf00663b3e1bd447d55b6ebd066b814a8d9c4434b224e9cb053a1fd038a58f3bf6b0c75b6f48f3c8d1ca398a730c133f86f244655f24c445324fdacd291d6d907f93efb24b59e509f2f370392f5e262fc106292792352d93800f0a1e3a389786619a622f6005cab78ea5f0b5b7ca91ad2a9c6c34fc4a3f9b0332b99e907ffa7f750cdc8342e12da78f13ad49953bae1751c983ce3cd3335288ac856f85057a7f05acba6465a1c6901ba30bc65b79fb7a847c42a5b4942d600ef316030f2ccafbc6f2e1ff0b46fb5c8517cd98c93f81acf370cfdab559bb4270d07db5466e2342d56c476089f473840434cbcdbd1853b487a6df346208d12c17a48fe50b73b96f640a9761f570a516f6157432b83dd18a1d05cc27b6f283a02fcfda147cf1471772e469961004bde7fa15857e7bf97b5a83c33fddbd9f4b2e2488f4ed5f7463c93f30b", "bfe966f3fabde6f38a2792ad59bc836bbca39de6eff64f15a42886deff6dfcc5", RSA_FDH_VRF_SHA256);

    test &= testVRFExample(key3072.n, key3072.d, key3072.e, "74657374", "22c9278e7171183cf6a3ce108f0400e308a9177c39a171f77777c106c966eb041824ce43fa56c5c77576646dd110e0b5d7f838bd5b1d1bf2c1feb1520397dd52d3cea6dbb49d786aa3bf3f5235e7692e583d290c7192102a6e0cb64f5229a326d4d00267fd75aae9687167ea0d3d450b2d63519ad605e64c77438728a190a129b1163939a5b7b0721b8d81efbf99a96944f63bf80ecc932fe40402d67c3e099a317cd1d13ac6947096308050ea6dad18fdb0958ae565d07d29e619673798f52b8d1dfdbf29b4641324ea6db5b9f35870acde7bf68e0829534d1c1f43ca9a16861efd82fb883e35d581f613d2dfbc89d01a84fdf081a3a850f2e865188cd995857222160c54780dc310a6ec100b9bac30f3af92e641360cad8dc255b56fa28e88ffcbef8ebe6ba8557e4ec44a7d0ebef882ade36db0d89be71ecaa2b35026c9d328d2384b54ae68de2ea70160ddde9aced5a8d896590fc185b408732cc04a249eff27501594902bf3af4a3743c4da50c5d62a74746007dedb8358ecfef78c75ab", "5bdf742667ad10080f4ca573ec66f751e82e4077d0db1b281df421af68d39412e70362dc5101b4b46e1e453eea7e0989", RSA_FDH_VRF_SHA384);

    test &= testVRFExample(key3072.n, key3072.d, key3072.e, "74657374", "1aa828e0a751074fed2fa776fd29336a84987c064eeebcd3a8129fb688b47eb7109987d01db0c3624ba7cc75e2f1ad60f5e204a250a329048bc34df34d41bfeea6651774d249ff9fc29aeabdf524400527aa1c4100b1af86b2dcc2e7aecc77f386b80f29ccd807cb705b5057431832dafe56733a1e7bfcba1d052a26d1a8512f297b5abad5afd64fbcf21b57531a9b2c8217c0d9f1c875c196d998f61e8017f6b6ebe7317545ed390e18305bc96abb1514ec271963d02bed91ccf029d022189f84bac8cfa216da54e39919118348dfea6f4f6532b49da7820ee2a21f42b762e107722ad0abf62271e0640d6b1c4d1a39b94ebd74b4283de2d6550cbdb1f29cac51671e9c8fc0ea0fdbb082a14a221e0531615f2bcfba0d70e99e4997cb00f81fcab2b955663220234a5e90f29bd08e6fa50dd92770d9e514e0f9eb27aee634877bcea681ffd7da2b5be2f80c1dde1243b17ac726401cf961c5ce06640eb93352402c1ebc59c92188c511b375d63124846b46017fe36dc13fc2d34dbd80b312e0", "9202b6715b7921c5eb35572ed9ebb85848d3345efadd665049ce889be46322586d4177864c9179468473518c6b6ac2e9c85ae5ee5fcd3c0d8e6d4d8f18be6238", RSA_FDH_VRF_SHA512);

    test &= testVRFExample(key4096.n, key4096.d, key4096.e, "73616d706c65", "745cc4b6cb75b925194374cdf91b498e8d687c5d9cae1eb5352446c554c2c43ac4aa3e2db5cf5e366df635ce156a277ebdbe78c5598588c98257069253127e57c9735b498f2939f14e1d019795cbd74cee2693acda2666624f174e8f666494aa12641bce0677acd20e5552d2690117bddb38678a18acdc380bd9d93f3b10960f9be0c141fc14f5f30da324ff14020cb5b8aed9fbca3fc44b4973d8e5527bd81f5ae5da67e5cc995abd1f7f9cdd3fa89b243fd4d5d5086ddb4eed77a2851fda1d4463f5ee037a4015aa40c420c2e609d5d0da4ef4a1622131022bdd9c9dc26d177b392663ea42050ef485fe9d53a8d28d84b82a21101bed5b213c82b578ce7c9c6f7c1bf9eca3c248ace9f8835f3850158749111ce1a3bdf5766add72a95a47c8866a4817c42c5cbd85d7bef52afab567e564f6625be9e04be6f7da012af68e6623ce4f29c692ba0b5f7665bb435a2168bd3b88aae0c6168bb87ea6977f35bb5ad833d96dd14d340f2a67b241b01fd8caf415842fd0a9dd5f4ccf4e70f15efdb85332e1df2bb186be15f7195176435e01bfd00592710023c3a88ac0eea7189b32296f865a310375111a5f11b74d0c74b98dfe4c41ccbe695ea801ba47f37b878c1ed0fff8302705b63c891209ea63defa892969e015a86d97945189444524e5fb660f2b9d1dce337a12e0d003ea6262ca3194515cc3aa10b1a03ac9dd6995b54d", "b663c5f90da1c12cd5d0e6d049679459e6f79f9fe16bc8b8e7e4d64d66500bd9", RSA_FDH_VRF_SHA256);

    test &= testVRFExample(key4096.n, key4096.d, key4096.e, "73616d706c65", "89d801e364fd48c3b8672e7d7abd8a2a1e5bd36bb1e38af5aaefa2f01cde686fa2e33f88fdcc8eb3babcf1c66cbbf7dcddb614041813990787be5feabe86bbec373d2cbf7c080caa0e37a339d5de1d1455de28f9bef76cd72500c669e9cab4599b55dc155d9dd5810174c170f646d3b0b459347c17347c0281eecf5055cf887d6bd0a2c962c77d5ff9355a53cea64c34ea0888110ec4eb32da69022e293a8843d4c06c9d6e020c594335720467a8337c6a939fb2c5d710f7bdab48a52f4e7483dae062c1b9f66f7c9038ba9ceef3d61cb4cc004319c94a267a2425b5f042cd7f1a17922d6596a88a6fefaef41fc87742f2badee7d7613179589b4d02611ac8fd7895d926f484f79542cdf7f034dd536c9596da2f588ac9840f6bb05875bd17107e7458cc5ea368a7699fd60c35b54253a718c26cf518712be9d86213b2c6bddd0b7dd169f9240e77bfc44223675454f9c5596ad2e6e607ea65011a721ecbfa993172ae372ae8743779b33278d25e11ced77b14bc481fce60e4fc10a8a211d8b359906509d6830c653d91c1a86865219db43f62c70ac6780644d2bd73c5c256527a3eaefaebaf1f220732417e17dbf598636616f70f2088969ac796a853dc8a5f270a1c505797e83d1675e4f40b59c150ca06c49bb0967a2e0c7e74eff9e182d0f7bb6f54f68fe788b89d2191c87bbf7f3927978449c2174baa581dc64a9c58ed", "8ec4d150788513c85eea3490d1a1ee1b7a397602d3f9c8b467527f09fab5252e539f82e8002825608295ebbba19644dd", RSA_FDH_VRF_SHA384);

    test &= testVRFExample(key4096.n, key4096.d, key4096.e, "73616d706c65", "17d7635cac33b0b72ea1c0afb1f681d1a96c5073ed9f88ed8bb54eb428d7b2db4ee3355eee512ddc7af50694b37fd389f990278e22095b2582c78c4ed6070b0c7382b0308b6d546141a9b0d6ebb3af97abd93c16a5d34a2d805d8aa444fed2297d017571a693d221fda094d40500ab9b203d397a7543e72b26b06e561d49696e01deebfed58b46611dd5a346e227d7519f8ffd1dc76a172c9f7f355c3e7e5ee7773edab00a22af5c39367f3779da68ce6da9f8a594f5f6149012501181653572fe5549a9c2bf36148b3bdc94feaedd600727fe5c11b7dcbfd73002ae08061cb4b84ba47f1bf8c5d46bc2acb7cb4964a6dca7eedc396e663a64121d93dade8b83cea09d76653cca1a8d20d6b7323a890651dc575025ba1be02d08c5946f50cde438339b06e8633198da0d467d2cac7d98ae62dd71353f6fb19aa9daac851d0ce237b21db93b91e518d5c1ac36cdf874975deb7aab3942acc3980f221f33ad1254eb8ac3138e087d045c4746e0b7eedcaf2a1a173559783eba8691555c1b0e468f8efe6501679b760038ed6fc9ce6aa5ae24b3f1178713793c8e5ee96035a2f0ee02e2d10ac098613358d3cff10f4dff3437f2a48252c5d6805288fbd7ee05356f80db12aaeabf6638677abf5b8eb2376fb76861cf1b817d5a0b878dae6beac44f078f37d982d941a77582a77784fabd632e28d664d9f705f31e24d1ca623dfac7", "6026f6defaf534cc79ce7c1b0370fb53e4825d2d44f549f696e06d693c39e852e21a5e3b6ff093618dd277b40678957e1b90e8e6ca742efed30dc309b3b242b8", RSA_FDH_VRF_SHA512);
    
    return test;

    
}

void printKey(const key & k) {
    cout<<"      <ul empty=\"true\" spacing=\"compact\">"<<endl;
    cout<<"        <li> p = " << str(k.p, NumBytes(k.p)) << "</li>"<<endl;
    cout<<"        <li> q = " << str(k.q, NumBytes(k.q)) << "</li>"<<endl;
    cout<<"        <li> n = " << str(k.n, NumBytes(k.n)) << "</li>"<<endl;
    cout<<"        <li> e = " << str(k.e, NumBytes(k.e)) << "</li>"<<endl;
    cout<<"        <li> d = " << str(k.d, NumBytes(k.d)) << "</li>"<<endl;
    cout<<"      </ul>"<<endl<<endl;

}

void generateTestVectors() {
    int exampleCounter=0;
    
    cout <<"     <t>There are three keys used in the nine examples below. First, we provide the keys. They are shown in hexadecimal big-endian notation.</t>"<<endl;
    cout<<"      <t>2048-bit key:</t>"<<endl;
    printKey(key2048);
    cout<<"      <t>3072-bit key:</t>"<<endl;
    printKey(key3072);
    cout<<"      <t>4096-bit key:</t>"<<endl;
    printKey(key4096);
    cout<<endl;


    
    cout<<"      <section numbered=\"true\" toc=\"default\">" << endl;
    cout<<"        <name>RSA-FDH-VRF-SHA256</name>"  << endl;
    cout<<endl<<"        <t>Example " << ++exampleCounter << ", using the 2048-bit key above:</t>"<<endl;
    generateTestVector(key2048.n, key2048.d, key2048.e, "", RSA_FDH_VRF_SHA256);
    cout<<endl<<"        <t>Example " << ++exampleCounter << ", using the 3072-bit key above:</t>"<<endl;
    generateTestVector(key3072.n, key3072.d, key3072.e, "74657374", RSA_FDH_VRF_SHA256);
    cout<<endl<<"        <t>Example " << ++exampleCounter << ", using the 4096-bit key above:</t>"<<endl;
    generateTestVector(key4096.n, key4096.d, key4096.e, "73616d706c65", RSA_FDH_VRF_SHA256);
    cout<<"      </section>"<<endl<<endl;

    cout<<"      <section numbered=\"true\" toc=\"default\">" << endl;
    cout<<"        <name>RSA-FDH-VRF-SHA384</name>"  << endl;
    cout<<endl<<"        <t>Example " << ++exampleCounter << ", using the 2048-bit key above:</t>"<<endl;
    generateTestVector(key2048.n, key2048.d, key2048.e, "", RSA_FDH_VRF_SHA384);
    cout<<endl<<"        <t>Example " << ++exampleCounter << ", using the 3072-bit key above:</t>"<<endl;
    generateTestVector(key3072.n, key3072.d, key3072.e, "74657374", RSA_FDH_VRF_SHA384);
    cout<<endl<<"        <t>Example " << ++exampleCounter << ", using the 4096-bit key above:</t>"<<endl;
    generateTestVector(key4096.n, key4096.d, key4096.e, "73616d706c65", RSA_FDH_VRF_SHA384);
    cout<<"      </section>"<<endl<<endl;

    cout<<"      <section numbered=\"true\" toc=\"default\">" << endl;
    cout<<"        <name>RSA-FDH-VRF-SHA512</name>"  << endl;
    cout<<endl<<"        <t>Example " << ++exampleCounter << ", using the 2048-bit key above:</t>"<<endl;
    generateTestVector(key2048.n, key2048.d, key2048.e, "", RSA_FDH_VRF_SHA512);
    cout<<endl<<"        <t>Example " << ++exampleCounter << ", using the 3072-bit key above:</t>"<<endl;
    generateTestVector(key3072.n, key3072.d, key3072.e, "74657374", RSA_FDH_VRF_SHA512);
    cout<<endl<<"        <t>Example " << ++exampleCounter << ", using the 4096-bit key above:</t>"<<endl;
    generateTestVector(key4096.n, key4096.d, key4096.e, "73616d706c65", RSA_FDH_VRF_SHA512);
    cout<<"      </section>"<<endl<<endl;

}


int main() {
    bool test = true;

    test &= testSHA256();
    test &= testSHA384();
    test &= testSHA512();

    
    test &= testMGF1();
   

    key2048.p = str(
                     "efb52a568fa3038fffb853e2183791c6bc81ceee86d20e8f9b6401dc79a8f1f6248d3a25fdb3f99245fce41667da038f59745b87cc1aed8b4a9c1d74e7d5c16cf7343f2b12f1b5055337369bf018fa07adc0d16f2164a516e80d2b4734f0c6563d6ee6d4a9e1a54e300cfe9ee679afc3d14a152dfb49b6cfb208bbf921f764af").toZZ();
    key2048.q = str(
                     "ecbca5ee88bbc635d8263aaba84f6502fdb2b4998a40f7c149133d840b6b1bd9a972fe2a981c770272b78fda213f76a062dd865dd116d4c8980975ee9347fe0f500567e51d78dbee4a34e626051cf018d7feb72f19189525d4f70b6467d0cef514633ab08a9e7a9ec632064b7b5e3e82128fe563757a614092fc5cf624d10e1b").toZZ();
    key2048.n = str( "ddaba77202bafb796b85bcec98958aa58ae2d117cbc66a6e75c4c2af983985a3064eaef93e2b03393256d94d75d6a6656b2956524ed8711898a0c3abae84371da0283bc5f433fc384d810a3c118ed302c0b03da16bee70b80ba3480e7acc1eb358b3f20fbe90cc4c8a7e2ba9e28b2a3800a5efbaa3c264f79b231f7cdc9577818df1bac60ef7a3f78a44f046fd29b0689556da7a7f61eefe67427f3f691aee0a4b1efe2ee2e0e6091143ebb7d69254c9d8ab01ff5e0ad7329f566082f9251e64f436c547e68de75351ea3a09746ceb7efed2d234121088aaed01696583c172ec88bc173a0d4d8ec43f4dcc18ff8379317e83ef9685536283368c9c6deb783075").toZZ();
    key2048.d = str( "d5c5ceab929a841e2a654536de4788f7f0a2a086d44bbb245f8aab3df00db924e8d644c3b502820f4cce98adacf09e73bc0e9762b50ae2b697aaa24914fa08b51758f59c07cf827341bb2a0597e126f9c69db031d60692c9cadf62842444696f08223154a1b0be752a325725748644e6d12935b1c66f983379773bcc8c65d06262e93b5bb774dd2784265c23e9a7fc5e8871eb6bcc9968a6bc360a98874b623ec59f41af0a9ecec6af095cb7e5aca11472363950dcbbfcf678fe003358b4ff0060a391daa45a1bd81c166b6221fb07e4f5da75e27d8d5fdbbf87ecbd7f5a4d804597070faaed22f197511b218788816689375245ddf7fa12337f3e7e898fb9d9").toZZ();
    key2048.e = str("010001").toZZ();
    test &= testKey (key2048);

    key3072.p = str(
                     "ee5adea28491084e6635bd73fd95649915a11da410d3f361c8eccc90a4b83425146da7b9e9d3994fd37d5fad7fb759ae451eb99b1102d4671ead23a2925133d19df49cf9d7e9dcb69fd7555ca095338d0d2a84abb6825050eaf5fffaeff17ccb0833c6079081dfcbd98ced36a593557d29d64b0e0253ce2ee4e07fe2a06269dfe5ca230fad221a593a69d9534b2521c1b41d116cafdee02106228ff41433605453e237777626953e79b46a84f50069e25b4f50496a928708abce30559eb183cf").toZZ();
    key3072.q = str(
                     "fb585bbc12f5695951f70a25e27682dc568acf56115ad749709b2a6e915cdd66dfa06db09b390c00b7c7ebeea00845f73c999d8ea9352b1128bdf10113c7500b76a03f6b38d0920b5589961549be3d841ccc306f3edd600a53b4b9d4fa1249af87af58dfb3ed694289477e853f7d062f58911f7bdb98033b001ee90f11b78f031cffac2b5a07e11b01a2a6c1cda059a728f8253a5ff87267623253fc022d3993b27e2f344b99eb6072ff7c7ee160724f8fbca562be49247ffae42b55ea79dad5").toZZ();
    key3072.n = str( "ea055cef495dec2d8fb3aef519ca87bd1575fa0ae15dd433f4a5f6c40d34ed6ba2388172ab7d2183ed970a669d427dc2774ced66a3f082b8e23e94e7de7532f4f30bb4a5bbf2e1db2cba0752858a7c7a9bb892c5d6af7e90a7cee8f0097d14498c8b482f86348640af61b66640538e834f23ba8f906048db0e57b6fdc162ba2a8a0eaedd5423f23d8f89413223d89f473029cba11a211eb59e41fb8f0b8ddc651d115d9f07ac30296485a9adbd71cc5d9e4a448bd6d70785e838a978b2e66513eb897c962e85f00a36cc0a3a613183d8bd1572f895901eb8155af9797dbd4aa14726f415712bf0eb29fa0a9e938cf5325def05d3af7e686227456d903233e316c8cc50341615e59b665f0a4a2c32cfccbf9469bdf89564481fb7afc27a7127741f79424e0a35cdc466dd33ef5a2067f75c86e06af9c03c68c6e78be5f1a4f49ea03569cd9f74c3a0ff290ca4ce2c2fa5b770ef8032b26a517c257b7b1c424622c5c04cf20f2290a268939e0cc79dfbac71842f94727b07bfafaded7db6c7f13b").toZZ();
    key3072.d = str( "6e68e957dbfd7c1862dc1b87780b9dcf0ff9016770bc9c09873b66194941d76218bf2013c1e4df9326dd4402f5df110656d2ec8ea87a28b2a1cb74e590872aeb765fe772ea21c57d6ab4ba0fad019189273f05c061719afd14af02277dd28d67c5ef50b75b521ca51819b9bcb44cb7c82be66776a45f490050dc0171e77374f1ed00d06f8beb09b711a9682107d8840d4a23edf6ac25441fdbf2b584dfa6a67cee21eb51c484f09416e11914e774713f1a17600fb9e4e99fbbd83fdcba4b09145dd9809449a1713777161c912d5d595362314b0ea9d1199e97780e8b3293a39af4019fcc746aaf78dbb7db06852c3358a9ed02ab1d15831a148b27b932c117445a4a6f5114edfa3ccc9a9862df714b78a5362aab5e30501b4a729af73e3cdcabe19aac4928b668969780ad33d9df206d904b978a055f4abbc64987744526856e16ef55962453e3ed7a8055b0d79d051c50c94584ec7501dbd4856d7a21e43f25d8749e683cca2f53f575af1d80f39d8e6932ffdf201d179cbf98314c4048c6c1").toZZ();
    key3072.e = str( "010001").toZZ();
    test &= testKey (key3072);

    key4096.p = str(
                     "ac803464c8b2082153e15d5a0698d0a2990397fa01c1edd6171a5315e743c99feb7acd31c37529d4f83405e657c390488d19f7da9ef9d9f9cff4b460d2a26eb10f90cf4aaf55a19e21dc3bb697723a673e12bbc6580adc7bb72adaddf4682d656ff5b992e62379bc7b0ac977f2bfbcfac634e04ed597ef302684be72c6bf7db10b80f452d412d09e63e017acba378ccc6ea58e683e5641d1e72248f3201a5632f4af7525e91f9e0733731d264fe36802f416cb3e182b21e67a12e3bfba9a9cf40a45ff32addfae78063933120238ac61fbb995300a8602aa84f993bed375d6ccba86ad0c8efa5f0950aa2c92779febce9d05fa7a1f0d6e5c0d785de93c108297").toZZ();
    key4096.q = str(
                     "feb39bb6ee78adfa524e9c0821f60c20d3cff74f8b49731d67ea27d218bcb20c87498d30dfd398bc23daff7b33dc330db93e6c0e5e6196e035446c6db7cfdb9868b9518d94670b31f9c4d2109cf32c9cc8ac2fc4a6c2e1078510522c81610a81a707997933ee24030b572a76ee51aa683312ecaa51d8558b3b19cccf65fc867354ae193fd5c4f5d5a7180c5ca1e90fcc42f6915dff69a3d1e49046f6c3ef841b262ba89ddcfde2ed3caeb5bd594181a76f6f1ce01fc65c6f925f6d5b77037c2cbf7b6047e19f7b9c846c80238f1c8284c33bfd90c79de91381bb883b0de568aaf4b4a3c3f9c98f92e9f6a51f010bcc1dacfd72bfdfda29f527d7f4913153bef7").toZZ();
    key4096.n = str( "aba03a8d8527bfc0cbea1cb9a100f4ee7870aedd74a6406f108f7a07f374336025357e256d655b342d73369102d03c7dcf3c14ed70aac7ebb62498c570068f71f1f165e14527f96d946ba839412252eacea604e7d6fd47a0bb9de776679fa9ad6485a076fda04a2015322626dcd2eb91d6b6248802e6d453eb4cbf5e1bfebed02d6ab36cfe3dd1e8b9749d4853a029940a0bed3aa3128fd8e2e6cd1115db15405bb3837012f56bdc5a6895ec5cc6bca52f7952cfe3c7d5d81d4d3d1c9a29a429eeedfbf58da0a5b17480875b8071f49eb568fc8d8c023c83b3ed870c3775aaf0578485d757b4ab18d8e5fdb30c2b5586047e6203ab1636e376f1c7031f171e2807a2058ece890cc8fae29ba819df76b45ddb514caee63db1c5e7a3af7468febff82bfe2eb79e3c5d1383b7ebee86f02e9cc1853f0f4486f7eb8fee23a2f794317ffd1c39471086dfbfc0e3c0f412f917225f5c551557f38c11f172eca257e4b5908a571e4daa7c7434903701f21937df87d10de9b50ada97e65855d5e786db8f3f86248b55d999ec31538bd1a409f3e13de46dccc05325774e89016708f8a96240ae1c16641e8b12ab07257e88aa50d3546e7a91073d85ed601775a3c08e9b7c242d20664dfd4e70a05218d9f2c7d760fab3cd772d9362527917cf5b51817e8c2aef51cb3b0dd8cb838097e513537f1d9c3c4708f44ed270db963c7d72cf11b1").toZZ();
    key4096.d = str( "1efd8dd524282b4deb04592f83cd226d353e53b5156d37d15652321ce16f281fc258487105b1f9a81054ef937bc89243bd7a01e56624d078d5a9021514c77a7b7eceb230dd45fc9a36e4c1b9a4f347b9b29af3e3d14466fcb5242c398b389f70f9e7cf33ed54564e38c597720909e513ae8bb149060d1c6612e506e13d78e087c2cbb39e88c22cf73315c598dbd0ddf1276743ed04a943644c84949ef32d5e4702c80581e54a7fb18879be28b21008dc63182b45f2c190f1b748cd322efc39f2807c64b4d06023cb49583418e7b6ac0f447eb2abf48e2ad335583cbc8dff2760c2cce1462346326708336f7e374253ed213e990044927c52d29591f414571e509afc2396a6af9843303a19673bcdec1e3fc7c0d6c3f43b4bf88ce83e2bdcfb5e39069fe32800cf3f6f6d9917b8083a66ce23a9ab5b0c95bbcc6dfc21d38dadecc20725b13ce2954ba1bd45ec151a8877fed317cac60b2afaa96c826df6d1c48e7c10649dccc75bdf905c362c6934da06c3ce30f5befc1cf776d7fda673625147b1108ecb5473f7f588279533eb184d748230443694b9761b01532ba707563ffa4962321e44fdb710025e8a6e00d29bf01ea040618ee111b5d79ac860083f91aa614777cc99d739458f7c53d63cea7155b118068e0b30b35ed6d0cfc75672f18d075157a3ed31bfa1ce2cea234357ec76117cc687c274636077abc437cb70a029").toZZ();
    key4096.e = str( "010001").toZZ();
    test &= testKey (key4096);
    
    
    test &= vrfExampleTests();

    if (!test) {
        cout << "ERROR: SOME TESTS FAILED" << endl;
        exit(-1);
    }

    
    else {
        generateTestVectors();
    }
    return test;
}
