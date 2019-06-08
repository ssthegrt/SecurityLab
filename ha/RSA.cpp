#include<bits/stdc++.h>
#include<gmp.h>
using namespace std;

void findGcd(mpz_t a,mpz_t b,mpz_t x,mpz_t y,mpz_t result)
{

	if(mpz_cmp_ui(a,0)==0)
	{
			mpz_set_ui(x,0);
			mpz_set_ui(y,1);
			mpz_set(result,b);
			return;
	}

	mpz_t x1,y1,temp1,temp2,temp3;
	
	mpz_inits(x1,y1,temp1,temp2,temp3,NULL);

	mpz_mod(temp1,b,a);
	
	findGcd(temp1,a,x1,y1,result);

	mpz_fdiv_q(temp2,b,a);
	
	mpz_mul(temp3,temp2,x1);

	mpz_sub(x,y1,temp3);

	mpz_set(y,x1);

	return;
}

string largeIntToStr(mpz_t k, int base)
{
	char str[1000];
	mpz_get_str(str,base,k);
	string s(str);
	return s;
}

void RSAParameters(mpz_t p,mpz_t q,mpz_t n,mpz_t e,mpz_t d)
{
	mpz_t phi,t1,t2;
	mpz_inits(phi,t1,t2,NULL);
	mpz_mul(n,p,q);
	mpz_sub_ui(t1,p,1);
	mpz_sub_ui(t2,q,1);
	mpz_mul(phi,t1,t2);
	gmp_printf("phi=%Zd\n",phi);
	mpz_set_ui(e,2);
	while(true)
	{
		mpz_t gcd,x,y;
		mpz_inits(gcd,x,y,NULL);
		findGcd(e,phi,x,y,gcd);
		if(mpz_cmp_ui(gcd,1)==0)
			{
				mpz_set(d,x);
				break;
			}
		mpz_add_ui(e,e,1);
	}
	if(mpz_cmp_ui(d,0)<0)
		mpz_add(d,d,phi);
	return;
}

void encrypt(string M,string E,string N,string &C)
{
	mpz_t m,e,n,c;
	mpz_inits(m,e,n,c,NULL);
	mpz_set_str(m,M.c_str(),10);
	mpz_set_str(e,E.c_str(),10);
	mpz_set_str(n,N.c_str(),10);
	mpz_powm(c,m,e,n);
	C=largeIntToStr(c,10);
	return;
}

void decrypt(string C,string D,string N,string &M)
{
	mpz_t m,d,n,c;
	mpz_inits(m,d,n,c,NULL);
	mpz_set_str(d,D.c_str(),10);
	mpz_set_str(c,C.c_str(),10);
	mpz_set_str(n,N.c_str(),10);
	mpz_powm(m,c,d,n);
	M=largeIntToStr(m,10);
	return;
}

void SharedKey(string Eb,string Da,string &SK)
{
	mpz_t e2,d1,sk;
	mpz_inits(e2,d1,sk,NULL);
	mpz_set_str(e2,Eb.c_str(),10);
	mpz_set_str(d1,Da.c_str(),10);
	mpz_mul(sk,e2,d1);
	SK=largeIntToStr(sk,10);
}

void reEncryption(string Ca,string SK,string N,string &Cb)
{
	mpz_t ca,sk,n,cb;
	mpz_inits(ca,sk,n,cb,NULL);
	mpz_set_str(ca,Ca.c_str(),10);
	mpz_set_str(sk,SK.c_str(),10);
	mpz_set_str(n,N.c_str(),10);
	mpz_powm(cb,ca,sk,n);
	Cb=largeIntToStr(cb,10);
}

void keyGen(string &PK,string &PR,string &N)//generate the public private key pair for RSA
{
	mpz_t p,q,n,e,d;
	mpz_inits(p,q,n,e,d,NULL);
	gmp_randstate_t st;
	unsigned long seed;
	seed= time(NULL);
	gmp_randinit_mt(st);
	gmp_randseed_ui(st,seed);
	mpz_t limit;
	mpz_init(limit);
	mpz_set_ui(limit,1e2);

	while(true)
	{
	mpz_urandomm(p,st,limit);
	if(mpz_probab_prime_p (p,25)==2)
		break;
	}

	while(true)
	{
	mpz_urandomm(q,st,limit);
	if(mpz_probab_prime_p (q,25)==2)
		break;
	}
	RSAParameters(p,q,n,e,d);
	cout<<"The parameters of RSA Algorithm are:"<<endl;
	gmp_printf("p=%Zd\n",p);
	gmp_printf("q=%Zd\n",q);
	gmp_printf("n=%Zd\n",n);
	gmp_printf("e=%Zd\n",e);
	gmp_printf("d=%Zd\n",d);
	PK=largeIntToStr(e,10);
	PR=largeIntToStr(d,10);
	N=largeIntToStr(n,10);
	return;
}

	
	

