#include<bits/stdc++.h>
#include<gmp.h>
using namespace std;
void gcd(mpz_t a,mpz_t b,mpz_t x,mpz_t y,mpz_t ans)
{
	if(mpz_cmp_si(a,0)==0)
	{
		mpz_init_set_si(x,0);
		if(mpz_cmp_si(b,0)<0)
			mpz_init_set_si(y,-1);
		else
			mpz_init_set_si(y,1);
		mpz_init_set(ans,b);
		mpz_abs(ans,ans);
		return;
	}
	mpz_t x1,y1,t1,t2;
	mpz_init(x1);
	mpz_init(y1);
	mpz_init(t1);
	mpz_init(t2);
	mpz_mod(t2,b,a);
	gcd(t2,a,x1,y1,ans);
	mpz_fdiv_q(t1,b,a);
	mpz_mul(t1,t1,x1);
	mpz_sub(x,y1,t1);
	mpz_init_set(y,x1);
	return;
}
void findparams(mpz_t  p,mpz_t q,mpz_t n, mpz_t e,mpz_t d)
{
	mpz_mul(n,p,q);
	mpz_t a,b,phi_n;
	mpz_inits(a,b,phi_n,NULL);
	mpz_sub_ui(a,p,1);
	mpz_sub_ui(b,q,1);
	mpz_mul(phi_n,a,b);
	mpz_set_ui(e,2);
	while(true)
	{
		mpz_t x,y,ans;
		mpz_inits(x,y,ans,NULL);
		gcd(phi_n,e,x,y,ans);
		if(mpz_cmp_ui(ans,1)==0)
		{
			mpz_set(d,y);
			break;
		}
		mpz_add_ui(e,e,1);
	}
	if(mpz_cmp_ui(d,0)<0)
		mpz_add(d,d,phi_n);
}
int main()
{
	mpz_t p,q,n,e,d;
	mpz_inits(p,q,n,e,d,NULL);
	string pt;
	cout<<"Enter the plain text :";
	getline(cin,pt);
	gmp_randstate_t st;
	unsigned long seed;
	seed= time(NULL);
	gmp_randinit_mt(st);
	gmp_randseed_ui(st,seed);
	mpz_t max;
	mpz_init(max);
	mpz_set_ui(max,100);
	while(true)
	{
		mpz_urandomm(p,st,max);
		if(mpz_probab_prime_p (p,25)==2)
			break;
	}
	while(true)
	{
		mpz_urandomm(q,st,max);
		if(mpz_probab_prime_p (q,25)==2)
			break;
	}
	findparams(p,q,n,e,d);
	cout<<"The parameters are:"<<endl;
	gmp_printf("p=%Zd\n",p);
	gmp_printf("q=%Zd\n",q);
	gmp_printf("n=%Zd\n",n);
	gmp_printf("e=%Zd\n",e);
	gmp_printf("d=%Zd\n",d);
	int size=pt.length();
	mpz_t ct[pt.length()];
	cout<<"\nEncrypted cipher text is : ";
	for(int i=0;i<pt.length();i++)
	{
		mpz_t M;
		mpz_init(M);
		int ascii= (int)pt[i];
		mpz_set_ui(M,ascii);
		mpz_init(ct[i]);
		mpz_powm(ct[i],M,e,n);
		gmp_printf("%Zd",ct[i]);	
	}

	cout<<"\n\nDecrypted plain text is : ";
	for(int i=0;i<size;i++)
	{
		mpz_t M;
		mpz_init(M);
		mpz_powm(M,ct[i],d,n);
		int ascii=mpz_get_ui(M);
		char val=(char)ascii;
		cout<<val;	
	}
	cout<<endl;
}