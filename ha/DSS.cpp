#include <bits/stdc++.h>
#include <gmp.h>
using namespace std;

void RandomInit(gmp_randstate_t st)
{
	unsigned long seed;
	seed= time(NULL);
	gmp_randinit_mt(st);
	gmp_randseed_ui(st,seed);
	return;
}

void findPrimitiveRoot(mpz_t P,mpz_t G)
{
	mpz_t r,x,ul,hl,temp;
	mpz_inits(r,x,ul,hl,temp,NULL);
	mpz_set_ui(r,2);
	mpz_sub_ui(ul,P,1);
	while(mpz_cmp(r,ul)<=0)//loop from r=2 to n-1
	{
		//gmp_printf("r=%Zd\n",r);
		mpz_set_ui(x,1);
		set<unsigned long int> s;
		while(mpz_cmp(x,ul)<=0)
		{
			mpz_powm(temp,r,x,P);
			//gmp_printf("temp=%Zd\n",temp);
			s.insert(mpz_get_ui(temp));
			mpz_add_ui(x,x,1);
		}
		if(mpz_cmp_ui(ul,s.size())==0)
			break;	
		mpz_add_ui(r,r,1);
	}
	mpz_set(G,r);
}

void keyGeneration(mpz_t q,mpz_t xa,mpz_t ya,mpz_t alpha)
{
	gmp_randstate_t st;
	RandomInit(st);
	mpz_t temp;
	mpz_inits(temp,NULL);
	mpz_sub_ui(temp,q,1);
	while(true)
	{
	mpz_urandomm(xa,st,temp);
	if(mpz_cmp_ui(xa,0)!=0||mpz_cmp_ui(xa,1)!=0)
		break;
	}
	// mpz_set_ui(xa,16);//hello
	//xa is now in range 2 to q-2
	mpz_powm(ya,alpha,xa,q);
	//public key is {q,alpha,ya}
	return;
}

void signMessage(mpz_t q,mpz_t ya,mpz_t xa,mpz_t alpha,mpz_t s1,mpz_t s2,mpz_t m)
{
	gmp_randstate_t st;
	RandomInit(st);
	mpz_t M,K,gcd,temp,temp2,inverseK;
	mpz_inits(M,K,gcd,temp,temp2,inverseK,NULL);
	mpz_urandomm(M,st,q);
	mpz_urandomm(m,st,q);
	mpz_sub_ui(temp,q,1);//temp=q-1
	//gmp_printf("Original text is:%Zd\n",M);
	while(true)
	{
		mpz_urandomm(K,st,q);
		if(mpz_cmp_ui(K,0)!=0)//1<=K<=q-1
		{
			mpz_gcd(gcd,K,temp);
			if(mpz_cmp_ui(gcd,1)==0)//if K and q-1 are relatively coprime
				break;
		}	
	}
	// mpz_set_ui(K,5);
	// mpz_set_ui(m,14);
	mpz_powm(s1,alpha,K,q);
	mpz_invert(inverseK,K,temp);
	mpz_mul(temp2,xa,s1);
	mpz_sub(temp2,m,temp2);
	mpz_mul(temp2,inverseK,temp2);
	mpz_fdiv_r(s2,temp2,temp);
	gmp_printf("S1=%Zd\n",s1);
	gmp_printf("S2=%Zd\n",s2);
}

void validateMessage(mpz_t q,mpz_t alpha,mpz_t m,mpz_t ya,mpz_t s1,mpz_t s2)
{
	mpz_t v1,v2,temp1,temp2;
	mpz_inits(v1,v2,temp1,temp2,NULL);
	mpz_powm(v1,alpha,m,q);
	unsigned long int sig1,sig2;
	sig1=mpz_get_ui(s1);
	sig2=mpz_get_ui(s2);
	mpz_pow_ui(temp1,ya,sig1);
	mpz_pow_ui(temp2,s1,sig2);
	mpz_mul(temp1,temp1,temp2);
	mpz_fdiv_r(v2,temp1,q);
	gmp_printf("V1=%Zd\n",v1);
	gmp_printf("V2=%Zd\n",v2);	
	if(mpz_cmp(v1,v2)==0)
	{
		cout<<"Signature is valid"<<endl;
	}
}

void validate(string Q,string Alpha,string M,string Ya,string S1,string S2)
{
	mpz_t q,alpha,m,ya,s1,s2;
	mpz_inits(q,alpha,m,ya,s1,s2,NULL);
	mpz_set_str(q,Q.c_str(),10);
	mpz_set_str(alpha,Alpha.c_str(),10);
	mpz_set_str(m,M.c_str(),10);
	mpz_set_str(ya,Ya.c_str(),10);
	mpz_set_str(s1,S1.c_str(),10);
	mpz_set_str(s2,S2.c_str(),10);
	validateMessage(q,alpha,m,ya,s1,s2);
}

void sign(string Q,string Ya,string Xa,string Alpha,string &S1,string &S2,string &M)
{
	mpz_t q,ya,xa,alpha,s1,s2,m;
	mpz_inits(ya,xa,alpha,s1,s2,m,NULL);
	mpz_set_str(q,Q.c_str(),10);
	mpz_set_str(ya,Ya.c_str(),10);
	mpz_set_str(xa,Xa.c_str(),10);
	mpz_set_str(alpha,Alpha.c_str(),10);
	signMessage(q,ya,xa,alpha,s1,s2,m);
	S1=largeIntToStr(s1,10);
	S2=largeIntToStr(s2,10);
	M=largeIntToStr(m,10);
}

void signKeyGen(string &Q,string &Xa,string &Ya,string &Alpha)
{
	mpz_t p,q,m,alpha,xa,ya,limit,s1,s2;
	mpz_inits(p,q,m,alpha,xa,ya,limit,s1,s2,NULL);
	gmp_randstate_t st;
	RandomInit(st);
	mpz_set_ui(limit,1e4);
	mpz_urandomm(p,st,limit);
	mpz_nextprime(q,p);//q is now the prime selected,next find the primitive root of q
	//mpz_set_ui(P,23);
	findPrimitiveRoot(q,alpha);
	// mpz_set_ui(G,9);
	
	keyGeneration(q,xa,ya,alpha);
	Q=largeIntToStr(q,10);
	Xa=largeIntToStr(xa,10);
	Ya=largeIntToStr(ya,10);
	Alpha=largeIntToStr(alpha,10);
}

