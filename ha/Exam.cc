#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include <bits/stdc++.h>

#define no_Of_Users 4
int M;
using namespace ns3;
using namespace std;
long long puba,pria,pubb,prib,proxypublicKey,proxyprivateKey;
long long p,q,N,phi_N;
Ipv4InterfaceContainer interfaces;
long long EncryptOrDecrypt(long long a, long long x, long long n)
{
  if( x==0 ) return 1;
  long long ans = 1;
  long long prd = EncryptOrDecrypt(a,x/2,n);
  ans = ( prd%n * prd%n )%n;
  if( x&1 ) ans = ( ans%n * a%n)%n;
  return ans;
}
long long gcdExtendedEuclidean(long long a, long long b, long long *x, long long *y) 
{ 
  if (a == 0) 
  { 
    *x = 0, *y = 1; 
    return b; 
  }
  
  long long x1, y1; 
  long long gcd = gcdExtendedEuclidean(b%a, a, &x1, &y1);  
  *x = y1 - (b/a) * x1; 
  *y = x1; 
  return gcd; 
} 
long long ModuloMultiplicativeInverse(long long a, long long b)
{
  long long x,y;
  gcdExtendedEuclidean(a,b,&x,&y);
  if(x<0) x+=b;
  return x;
}
long long HASH_Function(long long M)
{
	long long sum_of_digits = 0;
	while(M)
	{
		sum_of_digits += M%10;
		M /= 10;
	}
	return sum_of_digits;
}
string BufferCreate(long long message,long long signature)
{
  string a,b;
  stringstream aa,bb;
  aa<<message;bb<<signature;
  aa>>a;bb>>b;
  
  string Buffer = "";
  Buffer += a; Buffer +=" "; 
  Buffer += b; Buffer +=" ";
  return Buffer;
}
void generateKeys()
{

	cout<<"Enter p,q \n";
	cin>>p>>q;

	N=p*q;
	phi_N=(p-1)*(q-1);
	long long i;
	for(i=2;i<phi_N;i++)
	{
		long long x,y;
		if(gcdExtendedEuclidean(i,phi_N,&x,&y)==1)
		{
				puba=i;
				break;
		}
	}
	
	i++;
	for(;i<phi_N;i++)
	{
		long long x,y;
		if(gcdExtendedEuclidean(i,phi_N,&x,&y)==1)
		{
				pubb=i;
				break;
		}
	}
	i++;
	for(;i<phi_N;i++)
	{
		long long x,y;
		if(gcdExtendedEuclidean(i,phi_N,&x,&y)==1)
		{
				proxypublicKey=i;
				break;
		}
	}


	pria=ModuloMultiplicativeInverse(puba,phi_N);
	prib=ModuloMultiplicativeInverse(pubb,phi_N);
	proxyprivateKey=ModuloMultiplicativeInverse(proxypublicKey,phi_N);
}
void mySendFunction(const char *data,Ptr<Socket> sock, Ipv4Address dstaddr, uint16_t port)
{
  Ptr<Packet> p = Create<Packet> ( (uint8_t const*) data,(uint32_t)strlen(data));
  cout<<"Sending message "<<data<<" to port "<<port<<endl;
  sock->SendTo (p, 0, InetSocketAddress (dstaddr,port));
  cout<<"Sent successfully "<<endl;
}
void srcRecvFunction(Ptr<Socket> socket)
{

}
void ReceiveFunctionOfA(Ptr<Socket> socket)
{
  cout<<"********************************* Reached Alice *********************************"<<endl;

  Address from;
  Ptr<Packet> packet = socket->RecvFrom (from);
  packet->RemoveAllPacketTags ();
  packet->RemoveAllByteTags ();
  unsigned char buffer[1000];
  packet->CopyData(buffer,packet->GetSize());
  InetSocketAddress address = InetSocketAddress::ConvertFrom (from);
  cout<<"A Received " << packet->GetSize () << " bytes from " << address.GetIpv4 () << endl;   
  char data[1000];
  strcpy(data,(char*)buffer);

  string s(data);
  stringstream ss;
  ss<<s;
  long long CT1;ss>>CT1;

  cout<<"A Received "<<CT1<<endl;
  CT1=EncryptOrDecrypt(CT1,pria,N);
  CT1=EncryptOrDecrypt(CT1,pubb,N);
  cout<<"Dectypting using privateA and Encrypting using publicB\n";
  
  stringstream ss2;
  ss2<<CT1;
  string msg;
  ss2>>msg;
  cout<<"A Sending to Proxy "<<msg<<endl;
  mySendFunction(msg.c_str(),socket,interfaces.GetAddress(2),8000+2);
}
void challengeResponse(long long M)
{
	cout<<"B is authenticating A's public key\n";
	long long decrpt=EncryptOrDecrypt(M,prib,N);
	if(decrpt==puba)
		cout<<"A's public key has been authenticated.\n";
	else
		cout<<"Not Authenticated\n";
}
void ReceiveFunctionOfB(Ptr<Socket> socket)
{
  cout<<"********************************* Reached Bob *********************************"<<endl;

  Address from;
  Ptr<Packet> packet = socket->RecvFrom (from);
  packet->RemoveAllPacketTags ();
  packet->RemoveAllByteTags ();
  unsigned char buffer[1000];
  packet->CopyData(buffer,packet->GetSize());
  InetSocketAddress address = InetSocketAddress::ConvertFrom (from);
  cout<<"B Received " << packet->GetSize () << " bytes from " << address.GetIpv4 () << endl;   
  char data[1000];
  strcpy(data,(char*)buffer);

  string s(data);
  stringstream ss;
  long long msg,sig;
  ss<<s;
  ss>>msg;ss>>sig;

  cout<<"B Received Message and Signature: "<<msg<<" "<<sig<<endl;
  long long decrptmsg=EncryptOrDecrypt(msg,proxypublicKey,N);
  long long decrptsig=EncryptOrDecrypt(sig,proxypublicKey,N);
  long long hashcheck=HASH_Function(decrptmsg);
  if(hashcheck==decrptsig)
  	cout<<"Message is Authenticated\n";
  else
  	cout<<"Message is Corrupted\n";

  decrptmsg=EncryptOrDecrypt(decrptmsg,prib,N);
  cout<<"B Decrypted "<<decrptmsg<<endl;
}
void ProxyRecvFunction(Ptr<Socket> socket)
{
  cout<<"*********************************Reached Proxy  Server *********************************"<<endl;

  Address from;
  Ptr<Packet> packet = socket->RecvFrom (from);
  packet->RemoveAllPacketTags ();
  packet->RemoveAllByteTags ();
  unsigned char buffer[1000];
  packet->CopyData(buffer,packet->GetSize());
  InetSocketAddress address = InetSocketAddress::ConvertFrom (from);
  cout<<"Proxy Received " << packet->GetSize () << " bytes from " << address.GetIpv4 () << endl;   
  char data[1000];
  strcpy(data,(char*)buffer);

  string s(data);
  stringstream ss;
  ss<<s;
  long long text;ss>>text;

  cout<<"Proxy Received: "<<text<<endl;
  long long signedtext=HASH_Function(text);
  long long encryptsigntext=EncryptOrDecrypt(signedtext,proxyprivateKey,N);
  long long encrypttext=EncryptOrDecrypt(text,proxyprivateKey,N);
  string msg=BufferCreate(encrypttext,encryptsigntext);
  cout<<"Proxy signed the message "<<text<<" with "<<encryptsigntext<<endl;
  mySendFunction(msg.c_str(),socket,interfaces.GetAddress(3),8000+3);

}
int main(int argc,char* argv[])
{

	NodeContainer nodes;
	nodes.Create (no_Of_Users);

	CsmaHelper csma;
	csma.SetChannelAttribute ("DataRate", StringValue ("100Mbps"));
  	csma.SetChannelAttribute ("Delay", TimeValue (NanoSeconds (6560)));

	NetDeviceContainer CsmaDevices;
	CsmaDevices = csma.Install (nodes);

	InternetStackHelper stack;
	stack.Install (nodes);

	Ipv4AddressHelper address;
	address.SetBase ("10.1.2.0", "255.255.255.0");
	interfaces = address.Assign (CsmaDevices);

	Ipv4GlobalRoutingHelper:: PopulateRoutingTables();

	generateKeys();

	Ptr<Socket> socks[7];
	for(int i=0;i<no_Of_Users;i++)
	{
  	uint16_t myport = 8000;
  	socks[i] = Socket::CreateSocket (nodes.Get(i), TypeId::LookupByName ("ns3::UdpSocketFactory"));
  	Ipv4Address myaddr ( interfaces.GetAddress(i) );
  
  	InetSocketAddress my_ip_and_port = InetSocketAddress ( myaddr, myport+i );
  	socks[i]->Bind (my_ip_and_port);
  	if(i==1)
  		socks[i]->SetRecvCallback (MakeCallback (&ReceiveFunctionOfA));
  	else if(i==2)
  		socks[i]->SetRecvCallback (MakeCallback (&ProxyRecvFunction));
  	else if(i==3)
  		socks[i]->SetRecvCallback (MakeCallback (&ReceiveFunctionOfB));
  	else
  		socks[i]->SetRecvCallback (MakeCallback (&srcRecvFunction));
	}
	
	
	cout<<"PuA,PrA,Pub,Prb ,pubProxy,priProxy = "<<puba<<" "<<pria<<" "<<pubb<<" "<<prib<<" "<<proxypublicKey<<" "<<proxyprivateKey<<endl;
  	cout<<"Enter Message\n";
	cin>>M;

	cout<<"Challenge Response Authentication\n";
	long long decrptpubA=EncryptOrDecrypt(puba,pubb,N);
	cout<<"challengeResponse = "<<decrptpubA<<endl;
	challengeResponse(decrptpubA);

	long long CipherM=EncryptOrDecrypt(M,puba,N);
	string data;
	stringstream ss;
	ss<<CipherM;
	ss>>data;

	Packet::EnablePrinting();

	cout<<"Encrypting using publicA before sending A to get "<<data<<endl;
    Simulator::Schedule (Seconds (1),&mySendFunction, data.c_str(),socks[0],interfaces.GetAddress(1),8000+1);
    Simulator::Run ();
    Simulator::Destroy ();
    return 0;
}
