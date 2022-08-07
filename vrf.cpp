/**
 !!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!
 THIS CODE IS INSECURE AND NOT TO BE USED FOR ACTUAL CRYPTO!!!
 IT IS ALSO INEFFICIENT AND COBBLED TOGETHER JUST TO GET IT WORKING!!! DO NOT USE IT!!!
 It was written by Leo Reyzin as a reference implementation only, in order to generate test vectors.
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


#include <NTL/ZZ_pXFactoring.h>
#include <NTL/ZZXFactoring.h>
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
str MGF1(const str & mgfSeed, int maskLen, Hash h) {
    int hLen;
    
    switch (h) {
        case SHA256:
            hLen = 32;
            break;
        case SHA384:
            hLen = 48;
            break;
        case SHA512:
            hLen = 64;
            break;
        default:
            cout<< "ERROR -- UNKNOWN HASH ID" << endl;
            exit(-1);
    }
    int n = (maskLen-1)/hLen; // this gives floor of (maskLen-1)/hLen, which is equal to ceil of maskLen/hLen - 1
    str T;
    for (ZZ counter(0); counter <= n; counter++) {
        T = T || (mgfSeed || str(counter, 4)).hash(h);
    }
    return T.slice(0, maskLen);
}

str RSAFDHVRF_ProofToHash(const str & pi_string, Hash h) {
    str suite_string;
    switch (h) {
        case SHA256:
            suite_string = str('\1');
            break;
        case SHA384:
            suite_string = str('\2');
            break;
        case SHA512:
            suite_string = str('\3');
            break;
        default:
            cout<< "ERROR -- UNKNOWN HASH ID" << endl;
            exit(-1);
    }
    str proof_to_hash_domain_separator('\2');
    return (suite_string || proof_to_hash_domain_separator || pi_string).hash(h);
}

str RSAFDHVRF_Prove(const ZZ & n, const ZZ & d, const str & alpha_string, Hash h, bool verbose) {
    int k = (int)NumBytes(n);
    
    str suite_string;
    switch (h) {
        case SHA256:
            suite_string = str('\1');
            break;
        case SHA384:
            suite_string = str('\2');
            break;
        case SHA512:
            suite_string = str('\3');
            break;
        default:
            cout<< "ERROR -- UNKNOWN HASH ID" << endl;
            exit(-1);
    }
    str mgf_domain_separator('\1');
    str MGF_salt = str(ZZ(k), 4) || str(n, k);
    
    str EM = MGF1(suite_string || mgf_domain_separator || MGF_salt || alpha_string, k-1, h);
    if (verbose) cout << "          <li>EM = " << EM << "</li>" << endl;
    ZZ m = EM.toZZ();

    // RSASP1
    ZZ s = PowerMod(m, d, n);
    
    str pi_string(s, k);
    
    if (verbose) cout << "          <li>pi = " << pi_string << "</li>" << endl;
    
    if (verbose) cout << "          <li>beta = " << RSAFDHVRF_ProofToHash(pi_string, h) << "</li>" << endl;

    return pi_string;
}


bool RSAFDHVRF_Verify(const ZZ & n, const ZZ & e, const str & alpha_string, const str & pi_string, Hash h) {
    ZZ s = pi_string.toZZ();
    
    // RSAVP1
    if (s<0 || s>=n) return false;
    ZZ m = PowerMod(s, e, n);
    
    int k = (int)NumBytes(n);
    
    str suite_string;
    switch (h) {
        case SHA256:
            suite_string = str('\1');
            break;
        case SHA384:
            suite_string = str('\2');
            break;
        case SHA512:
            suite_string = str('\3');
            break;
        default:
            cout<< "ERROR -- UNKNOWN HASH ID" << endl;
            exit(-1);
    }
    str mgf_domain_separator('\1');
    str MGF_salt = str(ZZ(k), 4) || str(n, k);
    
    str EMPrime = MGF1(suite_string || mgf_domain_separator || MGF_salt || alpha_string, k-1, h);
    ZZ mPrime = EMPrime.toZZ();
    return m==mPrime;

}



bool testMGF1()
{
    /* These test vectors for MGF1 were created manually using the online SHA calculator at https://emn178.github.io/online-tools/sha256.html */
    str mgfSeed = str("deadbeef");
    str MGF1SHA256MaxOutput =  str ("a49eea4c082081ca8e405f9e8c880f57de8f7e2a121eabd1e2815c233b22e4538cc20abb816f996a86b3c5a3bf047e8c4eab43a7158434aa5e57c28576f2e04cd3e83885d191ce6fddaff08622befb66ea1b2b2ed092a90551d873303717cb605491a9ba17d6692cc489c606ac2429b69ac02a5cf350514df6b7d0858bab80ec");
    
    for (int i = 0; i<=MGF1SHA256MaxOutput.len; i++) {
        if (MGF1(mgfSeed, i, SHA256)!=MGF1SHA256MaxOutput.slice(0, i)) {
            cout << "ERROR MGF1 SHA256 output; length " << i << endl;
            return false;
        }
    }

    str MGF1SHA384MaxOutput =  str ("1d811399ad575afa5835154f773df112a8e571efe99998b454f7352f3bc8db7875c0412598bd6c72a646b2602fdf3bd79cbd76e0a3cbe94ede249e1aa3ad779338cf89353ab12c8842303ba13f71902ed707fc139bad91591e89521c12b8d02a92e4b70b227c8258c22be3bcacd79f65204e75f48a5a0c27629126e0d2ce9dd4b485ed19a4ff87d7a148082c0f293b2be950e50691225a104d5aa1f3f21c72bd5eb93ad78e5a9f931a9de5fe0620139d041cb62746b1ee85412d06bfaf2b8cff");

    for (int i = 0; i<=MGF1SHA384MaxOutput.len; i++) {
        if (MGF1(mgfSeed, i, SHA384) != MGF1SHA384MaxOutput.slice(0, i)) {
            cout << "ERROR MGF1 SHA384 output; length " << i << endl;
            return false;
        }
    }

    str MGF1SHA512MaxOutput =  str ("60d84c125a67aa2bd748ff356d054ba992c8004395f4f1d1d51e2011360ee4248b4e22956e9b8a19f8ca80aefa3138db9d09b3cd25d975d65865259ea8d69e1f26b5c693f61289b8a2d6128f38e490442a1c6e5154ad2d64cb6369fb78eec8b9ce3520d330f9d1b88ec8cfaf8295988e291702cd5b69b155518ad5e5aedae258f2e3f66d79d27271220c30bafcb07f0c952183f016a74b4e1e67a27251459c0c4985a4f231843957fcccb804af6a07d9340c9df0636a560a0e9e0cb5639211413d08c7ca253dffe391e90004140e09b040fffdc42c640cda09d00625fb59e29832412703cc667c1de24fb81ac10c815896278d47db42314631b4777189b5ce70");

   for (int i = 0; i<=MGF1SHA512MaxOutput.len; i++) {
        if (MGF1(mgfSeed, i, SHA512) != MGF1SHA512MaxOutput.slice(0, i)) {
            cout << "ERROR MGF1 SHA512 output; length " << i << endl;
            return false;
        }
    }

    return true;

}

bool testVRFExample(const str & n_string, const str & d_string, const str & e_string, const char * alpha_input, const str & pi_string, const str & beta_string, Hash h) {
    ZZ n = n_string.toZZ();
    ZZ d = d_string.toZZ();
    ZZ e = e_string.toZZ();
    str alpha(alpha_input);
    
    str ret = RSAFDHVRF_Prove(n, d, alpha, h, false);
    if (ret != pi_string) {
        cout << "ERROR VRF Example Test Wrong Proof" << endl;
        return false;
    }
    
    if (RSAFDHVRF_ProofToHash(pi_string, h) != beta_string) {
        cout << "ERROR VRF Example Test Wrong Beta" << endl;
        return false;
    }
    
    if (!RSAFDHVRF_Verify(n, e, alpha, ret, h)) {
        cout << "ERROR VRF Example Does Not Verify" << endl;
        return false;
    }
    return true;
    
}

void generateTestVector(const str & n_string, const str & d_string, const char * alpha_input, Hash h) {
    cout <<  "        <ul empty=\"true\" spacing=\"compact\">"<<endl;
    
    cout << "          <li>n " << n_string << "</li>" << endl;
    cout << "          <li>d = " << d_string << "</li>" << endl;
    
    str alpha(alpha_input);
    cout << "            <li>alpha = " << alpha ;
    if(alpha.len == 0) cout << " (the empty string)";
    else if(alpha.len == 1) cout << " (1 byte)";
    else cout << " (" << alpha.len << " bytes)";
    cout <<"</li>" << endl;
    for (int i=0; i<alpha.len; i++) cout << alpha.s[i];
    
    RSAFDHVRF_Prove(n_string.toZZ(), d_string.toZZ(), alpha, h, true);
    cout<<"        </ul>"<<endl;
}


int main() {
    bool test = testMGF1();
    
    str n ("64f70acdc41c0ee7cb4961760368e34889c058ad3c7e578e8e72ed0d2fd1c7cfbb8beffd107204d544919db9d2470669c969e178d4deb8393daec4584ca9f162805c9ba46e617d89d4ab6480b0873b1cb92cf7232c88f013931ffe30f8ddf2cddbff4402bcb721985d2bb2eee5382dd09210b5d1da6b6b8207fe3e526de54efb55b56cd52d97cd77df6315569d5b59823c85ad99c57ad2959ec7d12cdf0c3e66cc57eaa1e644da9b0ca69b0df43945b0bd88ac66903ec98fe0e770b683ca7a332e69cba9229115a5295273aeeb4af2662063a312cbb4b871323f71888fd39557a5f4610ea7a590b021d43e5a89b69de68c728ce147f2743e0b97a5b3eb0d6ab1");
    str d ("39134e9033a488e8900ad3859b37d804519ae2864c04400ade8c2965a2fabc31ba9bc8f70e2ce67e895ca8053bd1dad6427e106ff626518e4a4859c670d0411ca5e3b438a80d84a23e0f05a99a2158514c7d16d8537cb5fadad8e3215c0e5c0bf3a9c210aa0dfc77dd73ae9b4e090c1d33f52e538b5dde508ba43626f2e906546773ba7401aa6b68ab1151da528336ddafc9a6f2995d89ec282bc555fe41e776216576c0aafb66ef00b718e6c62afd51faf82e7b5a1d430591465b2188fa286ce778eb6a1b346b58331c7820b4142fb808e59ec910aa9b6d340dea673ae7be2d9e1fa91494e40372bcfb92da5fe236dc93b30b0a59b20af8edf3a10e3ea6dfe1");
    str e ("010001");
    
    test &= testVRFExample(n, d, e, "", "406581e350c601d6d7518ac928f6753929c56a7480a4a3d011ed65e5f61ca033accd45c03cac2dddcd61b909cedd0df517a1bba4705c9d04a2a8c7d735d24bc3e59b263cc8c18d5f6e2712747d809df7868ac720f90ffd3d7c7b78f3d75f14a9755ea8138804806f4739429d1a313b3abaaf89ce97fbdf10bc01d66723b0b38ad5dc51c87e5f852e2c8fc923cf0f9c86bb7bf8ae808532fcb8a981338d5b13278e66e19915e41c6fbd09f1fce3300da422fbf46f706d1c79f298c740926e14069f83dae52a25bad684e420ad5fc8af3b02e0cf3f79782fb6e7e65abe5e1f6b4fe41f20339b2986fe39f7ce4ceb9c2490d5229e9bfda93150d6800880c411daae", "d065ca3be8716236e99f64139adf481090f0a0c839f86ffda3c4fad948166af0", SHA256);

    test &= testVRFExample(n, d, e, "72", "3d396dc417bee1975ff63c4e8b43b9417be03a91d5eb47309790d74100271342d6dc11511333ec4bc42aea3e02640dc870665044e85085c3dea43eedeb266d9b2de3824aca18b8de3e4d198bde808d80a2a10f0f4bd73fbc7cc36da44cb68af3161b2264e737dcd2d669252abb29f275c971ff6b8234876b7d1ff3d4d05197fe563d6ae92685dccbbbb689b4837da42fe47433019d9bfc50001b11708bf9f656532febf674119c0d67e27714195722fd977e0fc35d7325b5fb3ecb54df53986e01a809d0e5ec442fdacc3d271e7ab5480b8eb18f25cd3baf6a47abc6bf027e8dedef911f2bec367fa5d65e106f314b64cc1d9534d4f26fa034035a43852be66a", "a229210b84f0bb43b296075f226dee433cf2727cd6c2e4871afdeb77414f6a47", SHA256);

    test &= test && testVRFExample(n, d, e, "af82", "57b07056abc6851330b21ae890fd43ea53b4435319748cf8dba82148ee381c11d21a8660a8714aa59abaac2b7d0141ac4e85b1113b144328eb11461a7f26086896036fc49579a58a2516cecd274946f8dd82fef31652dfe2e2b495966cd6193a1bd197ef6e3472f30bfe14827dd968ea3bf8310dc002a765a0d54b12c3c9627309800b74701a3f7d07a02db0a6ca3a639e60726059727313818a6b671bebe18f078713ced33e50acbfd1e661ec89c5e82b8e1e07f6293f45474aa57d084da46a2437932491d92a87b3393bb0ec62254a3eca19e1004756867839671f84f7a2378097f334832f4aa0442fc5f8637fb2220bb3f2dca247927f0d49ae1c1b2e7455", "ebc5582b6aaf23c424ec1c74e1b8250327c957967fa37566284dac8400e62032", SHA256);

    
    
    generateTestVector(n, d, "", SHA256);
    generateTestVector(n, d, "72", SHA256);
    generateTestVector(n, d, "af82", SHA256);

    if (!test) {
        cout << "ERROR: SOME TESTS FAILED" << endl;
    }
    return test;
}
