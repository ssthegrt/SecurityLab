#include<bits/stdc++.h>
#define ll long long int
#define LIMIT 1000007
using namespace std;

vector<ll> prime;
bool isPrime[LIMIT];

void generate_primes()
{
	//Generates Primes using Sieve of Eratosthenes
	memset(isPrime,true,sizeof(isPrime));
	for(ll i=2;i<LIMIT;i++)
	{
		if(isPrime[i])
		{
			prime.push_back(i);
			for(ll j=i*i;j<LIMIT;j+=i) isPrime[j]=false;
		}
	}
}

ll generate_xa(ll p)
{
	ll xa;
	while(1)
	{
		xa=rand()%p;
		if(xa>1 && xa<p-1) break;
	}
	return xa;
}

ll exponent(ll M,ll e,ll n)
{
	if(e==0) return 1;
	ll prod=1;
	if(e%2!=0) prod=(prod%n * M%n)%n;
	ll tmp=exponent(M,e/2,n);
	tmp = (tmp%n * tmp%n)%n;
	return (prod%n * tmp%n)%n;
}

ll extendedgcd(ll a, ll b)
{
	ll q,r,x1=1,x2=0,x;
	do
	{
		q=a/b;
		r=a%b;

		x=x1-q*x2;
		a=b; b=r;
		x1=x2; x2=x;
	}while(r!=0);
	return x1;
}

ll encrypt(ll M,ll p,ll q,ll y_a,ll &S1,ll &K_inv)
{
	ll K,m=M%p;
	while(1)
	{
		K=(rand()%(p-1))+1;
		if(isPrime[K]) break;
	}

	S1=exponent(q,K,p);
	if(S1<0) S1+=p;
  	K_inv=extendedgcd(K,p-1);
	return m;
}


int main()
{
	srand(time(NULL));
	generate_primes();

	ll p,q,xa,ya,M,S1,C2;
	cout<<"Enter a large prime number"<<endl;
	cin>>p;
	cout<<"Enter the smaller generator q"<<endl;
	cin>>q;

	xa=generate_xa(p);//Random Number xa between 1 and p-1
	ya=exponent(q,xa,p);
	if(ya<0) ya+=p;

    cout<<"Public Key is: ( "<<p<<" , "<<q<<" , "<<ya<<" )\n";

    cout<<"Enter message to encrypt between 0 and "<<p-1<<"\n";
    cin>>M;  //

	ll m=encrypt(M,p,q,ya,S1,C2);
	ll S2=(C2%(p-1) * (m%(p-1) - (xa%(p-1) * S1%(p-1))%(p-1) )%(p-1) )%(p-1);
	if(S2<0)
		S2=S2+p-1;
	cout<<"The signature is : "<<S1<<" and "<<S2<<endl;
  	ll V1= exponent(q,m,p);
	ll prod1= exponent(ya,S1,p);
	ll prod2= exponent(S1,S2,p);
	ll V2= (prod1%p * prod2%p)%p;

  	cout<<" V1 = "<<V1<<" V2= "<<V2<<endl;
	cout<<"The signature is verified\n";
	return 0;
}
