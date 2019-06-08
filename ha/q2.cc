#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/csma-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include <bits/stdc++.h>
#include <gmpxx.h>

using namespace ns3;
using namespace std;

#define ll long long int
#define pll pair<ll,ll>
#define MAXN 100
#define pb push_back

ll users,levels,M,n,phi_n,p,q,root=0;
ll sender,receiver;
pll key_of_level[10];
ll par[MAXN];
ll child[MAXN];
Ipv4InterfaceContainer interfaces;

ll ModularExponent(ll a, ll x, ll n)
{
  if( x==0 ) return 1;
  ll ans = 1;
  ll prd = ModularExponent(a,x/2,n);
  ans = ( prd%n * prd%n )%n;
  if( x&1 ) ans = ( ans%n * a%n)%n;
  return ans;
}

ll gcdExtended(ll a, ll b, ll *x, ll *y) 
{ 
	if (a == 0) 
	{ 
		*x = 0, *y = 1; 
		return b; 
	} 
  
	ll x1, y1; 
	ll gcd = gcdExtended(b%a, a, &x1, &y1);  
	*x = y1 - (b/a) * x1; 
	*y = x1; 
	return gcd; 
} 

ll ModuloMultiplicativeInverse(ll a, ll b)
{
  ll x,y;
  gcdExtended(a,b,&x,&y);
  if(x<0) x+=b;
  return x;
}


string createPacketBuffer(ll Sender,ll Reciever,ll Message)
{
	string a,b,c;
	stringstream aa,bb,cc;
	aa<<Sender; bb<<Reciever; cc<<Message;
	aa>>a; bb>>b; cc>>c;

	string Buffer = "";
	Buffer += a; Buffer +=" "; 
	Buffer += b; Buffer +=" ";
	Buffer += c; Buffer +=" ";
	return Buffer;
}

void mySendFunction(const char *data,Ptr<Socket> sock, Ipv4Address dstaddr, uint16_t port)
{
	Ptr<Packet> p = Create<Packet> ( (uint8_t const*) data,(uint32_t)strlen(data));
	cout<<"Sending message "<<data<<" to port "<<port<<endl;
	sock->SendTo (p, 0, InetSocketAddress (dstaddr,port));
	cout<<"Sent successfully "<<endl;
}

void rootRecvFunction(Ptr<Socket> socket)
{
	cout<<"######################## Reached root ##############################"<<endl;
	Address from;
	char data[1000];
	Ptr<Packet> packet = socket->RecvFrom (from);
	packet->RemoveAllPacketTags ();
	packet->RemoveAllByteTags ();
	packet->CopyData((unsigned char*)data , packet->GetSize());
	InetSocketAddress address = InetSocketAddress::ConvertFrom (from);
	cout<<"Destination Received " << packet->GetSize () << " bytes from " << address.GetIpv4 () << endl;
	
	string s(data);
	ll a,b,c;
	stringstream ss;
	ss<<s;
	ss>>a>>b>>c;
	if(a == 2 ) 
	{
		cout<<"Root received messasge from 2"<<endl;
		string msg = createPacketBuffer(1,3,c);
		mySendFunction(msg.c_str(),socket,interfaces.GetAddress(3-1),8000+(3-1));
		cout<<"Root sent message to 3 "<<endl;
	}
	else
	{
		cout<<"Root received message from 3 "<<endl;
		string msg = createPacketBuffer(1,2,c);
		mySendFunction(msg.c_str(),socket,interfaces.GetAddress(2-1),8000+(2-1));
		cout<<"Root sent message to 2 "<<endl;
	}

}



void myRecvFunction(Ptr<Socket> socket)
{
	cout<<"######################## Reached " <<socket->GetNode()->GetId()+1 <<" ##############################"<<endl;

	Address from;
	Ptr<Packet> packet = socket->RecvFrom (from);
	packet->RemoveAllPacketTags ();
	packet->RemoveAllByteTags ();
	unsigned char buffer[1000];
	packet->CopyData(buffer,packet->GetSize());
	InetSocketAddress address = InetSocketAddress::ConvertFrom (from);
	cout<<"Destination Received " << packet->GetSize () << " bytes from " << address.GetIpv4 () << endl;   
	char data[1000];
	strcpy(data,(char*)buffer);

	string s(data);
	stringstream ss;
	ss<<s;
	ll rid,sid,C,M;

	ss>>sid; ss>>rid; ss>>C;
	
	int mylevel = log2(rid);
	if(rid == child[sid])
	{
		cout<<"Data recievied from parent is : "<<C<<endl;
		M = ModularExponent(C,key_of_level[mylevel].second,n);
		cout<<"############################ Decrypting "<<C<< " ############################"<<endl;
		cout<<"Key used = "<<key_of_level[mylevel].second<<endl;
		cout<<"Data decrypted : "<<M<<endl;
		if(rid == receiver)
		{
			cout<<"Receiver received the messag integer :  "<<M<<endl;
			return ;
		}
		string msg = createPacketBuffer(rid,child[rid],M);
		mySendFunction(msg.c_str(),socket,interfaces.GetAddress(child[rid]-1),8000+child[rid]-1);

		
	}
	else if(rid == par[sid])
	{
		cout<<"Data recievied : "<<C<<endl;
		M = ModularExponent(C,key_of_level[mylevel].first,n);
		cout<<"############################ Encrypting "<<C<< " ############################"<<endl;
		cout<<"Key used = "<<key_of_level[mylevel].first<<endl;
		cout<<"Data encrypted : "<<M<<endl;
		string msg = createPacketBuffer(rid,par[rid],M);
		mySendFunction(msg.c_str(),socket,interfaces.GetAddress(par[rid]-1),8000+par[rid]-1);
		
	}

	
}

int main(int argc, char *argv[])
{
	cout<<"Enter the number of users in the tree. Should be of the form 2^n-1..."<<endl;
	cin>>users;

	cout<<"Enter two primes p and q "<<endl;
	cin>>p>>q;
	n = p*q;
	phi_n = (p-1)*(q-1);

	levels = log2(users) + 1;
	for(int i=1;i<levels;i++) 
	{
		ll e,d;
		cout<<"Enter the public key shared in level "<<i<<" coprime to "<<phi_n<<endl;
		cin>>e;
		d = ModuloMultiplicativeInverse(e,phi_n);
		key_of_level[i] = make_pair(e,d);
		cout<<"Key of level "<<i<<" is : "<<"( "<<e<<" , "<<d<<" ) "<<endl;
	}

	int sid,rid;
	cout<<"Enter the sender and reciever id at same levels"<<endl;
	cin>>sid>>rid;
	int l1 = log2(sid);
	int l2 = log2(rid);
	if(l1!=l2) 
	{
		cout<<"Sender and reciever are from different levels. Exiting..."<<endl;
		return 0;
	}
	memset(par,0,sizeof par); 
	memset(child,0,sizeof child);
	root=1;

	ll current = sid;
	while(current!=root)
	{
		par[current] = current/2;
		current /= 2;
	}
	current = rid;
	while(current!=root)
	{
		child[current/2] = current;
		current /= 2;
	}
	sender = sid;
	receiver = rid;
	cout<<"Enter the integer message to be sent : "<<endl;
	cin>>M;
	cout<<"############################ Encryptin "<<M<< " ############################"<<endl;
	cout<<"Key used = "<<key_of_level[l1].first<<endl;
	ll C;
	C = ModularExponent(M,key_of_level[l1].first,n);

	cout<<"Encrypted message is "<<C<<endl;


	NodeContainer nodes;
	nodes.Create (users);

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

	Ptr<Socket> socks[MAXN];
	for(int i=0;i<users;i++)
	{
		uint16_t myport = 8000;
		socks[i] = Socket::CreateSocket (nodes.Get(i), TypeId::LookupByName ("ns3::UdpSocketFactory"));
		Ipv4Address myaddr ( interfaces.GetAddress(i) );
		
		InetSocketAddress my_ip_and_port = InetSocketAddress ( myaddr, myport+i );
		socks[i]->Bind (my_ip_and_port);
		if(i!=0)
		{
			socks[i]->SetRecvCallback (MakeCallback (&myRecvFunction));
		}
		else
		{
			socks[i]->SetRecvCallback (MakeCallback (&rootRecvFunction));
		}
	}
	string msg = createPacketBuffer(sender,par[sender],C);

	cout<<"Inital packet = "<<msg<<endl;
	Simulator::Schedule (Seconds (1),&mySendFunction, msg.c_str() , socks[sender-1], interfaces.GetAddress(par[sender]-1), 8000+(par[sender]-1));
	Simulator::Run ();
	Simulator::Destroy ();
	return 0;
}