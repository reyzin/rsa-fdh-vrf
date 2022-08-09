**INSECURE and INEFFICIENT** reference implementation for the four variants of the [RSA-FDH-VRF](https://github.com/cfrg/draft-irtf-cfrg-vrf) (see also [IETF's site, which may be a bit behind](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-14)).
Requires [GMP](https://gmplib.org) and [NTL](https://shoup.net/ntl).  

**!!!!!!!!!!!!!!!!!!!!!!!!! WARNING !!!!!!!!!!!!!!!!!!!!!!!!!**

THIS CODE IS INSECURE AND NOT TO BE USED FOR ACTUAL CRYPTO!!!
IT IS ALSO INEFFICIENT AND COBBLED TOGETHER TOO QUICKLY TO BE ANY GOOD!!! 
DO NOT USE IT!!!

It was written as a reference implementation only, in order to generate test vectors.

------------------------------------------------------------------

Compiling notes: if you are having trouble compiling, check what version
of GMP and NTL you have. Mine worked with GMP 6.1.2 and NTL 10.5.0. 
