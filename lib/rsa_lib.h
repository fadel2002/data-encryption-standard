#ifndef RSA_LIB_H   
#define RSA_LIB_H

/* 
	Function List On CHAT Class:

    int gcd(int a, int h);
    long long int modexp(long long int b, long long int e, long long int m);
	int decrypt(int key, long long int D = 0, long long int N = 0)
    int encrypt(int key, long long int E = 0, long long int N = 0)
    pair<int, int> getPublicKey();
    long long int generateKeyDistribution(int P, int Q)
*/

class RSA{
    // public key = {e, n}
	// private key = {d, n}
    long long int n, e, d, p, q;
public:
    RSA(long long int P, long long int Q){
        p = P; 
        q = Q;
        n = p * q;
        e = 2;
        long long int phi = (p - 1) * (q - 1);
        while (e < phi) {
            if (gcd((int)e, (int)phi) == 1)
                break;
            else
                e++;
        }
        d = 2;
        while(((d*e) % phi) != 1ll){
            d++;
        }
    }
    int gcd(int a, int h){
        int temp;
        while (1) {
            temp = a % h;
            if (temp == 0)
                return h;
            a = h;
            h = temp;
        }
    }
    long long int modexp(long long int b, long long int e, long long int m){
        long long int r = 1;
        while(e > 0ll){
            if((e & 1) == 1){
                r = (r * b) % m;
            }
            e >>= 1ll;
            b = (b * b) % m;
        }
        return (long long int)r;
    }
    int decrypt(int key, long long int D = 0, long long int N = 0){
        // Decryption (key ^ d) % n
        if (D != 0 && N != 0) return (int)modexp(key, D, N);
        else return (int)modexp(key, d, n);
    }
    int encrypt(int key, long long int E = 0, long long int N = 0){
        // Encryption (key ^ e) % n
        if (E != 0 && N != 0) return (int)modexp((long long int)key, E, N);
        else return (int)modexp((long long int)key, e, n);
    }
    pair<int, int> getPublicKey(){
        return make_pair((int)e, (int)n);
    }
    long long int generateKeyDistribution(int P, int Q){
        long long int val = 1;
        srand(time(0));
        // val <= p*q-2 terkecil
        while(true){
            val = 1;
            for (int i = 0; i < 5; i++) 
                val = val * rand() % (p*q-1);
            if (val != 1 && val != 0 && val != 2) break;
        }
        return val;
    }
};

#endif
