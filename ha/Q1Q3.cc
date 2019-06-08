#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "RSA.cpp"
#include "DSS.cpp"
using namespace ns3;

string PKa,PRa,Na;
string SK;
string PKb,PRb,Nb;
string authenticationMessage;
string Q,Xa,Ya,Alpha;//DSS Parameters
NS_LOG_COMPONENT_DEFINE ("Proxy reencryption");

void SendStuff (char *data,Ptr<Socket> sock, Ipv4Address dstaddr, uint16_t port)
{
  Ptr<Packet> p = Create<Packet> ();
  uint8_t buffer[1000];
  bzero((char*)buffer,100);
  uint32_t size;
  strcpy((char*)buffer,data);
  size = strlen((char*)buffer);
  // cout<<"APPLE:"<<size<<endl;
  Ptr<Packet> p1 = Create<Packet> (buffer,size);
  p->AddAtEnd(p1);
  sock->SendTo (p, 0, InetSocketAddress (dstaddr,port));
  return;
}

void mySendFunction(const char *data,Ptr<Socket> sock, Ipv4Address dstaddr, uint16_t port)
{
  Ptr<Packet> p = Create<Packet> ( (uint8_t const*) data,(uint32_t)strlen(data));
  cout<<"Sending message "<<data<<" to port "<<port<<endl;
  sock->SendTo (p, 0, InetSocketAddress (dstaddr,port));
  cout<<"Sent successfully "<<endl;
}

void srcSocketRecvMA(Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom (from);
  cout<<"Packet:"<<*packet<<" SIZE:"<<packet->GetSize()<<endl;
  packet->RemoveAllPacketTags ();
  packet->RemoveAllByteTags ();
  char buffer[1000];
  packet->CopyData((unsigned char*)buffer,packet->GetSize());
  InetSocketAddress address = InetSocketAddress::ConvertFrom (from);
  cout<<"Source Received " << packet->GetSize () << " bytes from " << address.GetIpv4 () << " Data:" <<buffer<<endl;
  string c(buffer);
  c=c.substr(0,packet->GetSize());
  cout<<"The cipher text sent from B to A:"<<c<<endl;
  cout<<"Trying to decrypt using B's public key to verify it is B"<<endl;
  string m;
  decrypt(c,PKb,Nb,m);
  cout<<"The message decrypted is:"<<m<<endl;
  cout<<"The message "<<m<<" is same as the original message "<<authenticationMessage<<" and hence mutual authentication is achieved"<<endl;
  //socket->SetRecvCallback (MakeCallback (&srcSocketRecv));

  //now prepare for sending the cipher text to proxy server

  string ca;
  encrypt(m,PKa,Na,ca);
  cout<<"The cipher text being send by A to proxy server is:"<<ca<<endl;
  char data[1000];
  strcpy(data,ca.c_str());
  uint16_t proxyport = 12348;
  Ipv4Address proxyaddr ("10.0.0.1");
  mySendFunction(data, socket, proxyaddr, proxyport);
}

void midSocketRecv (Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom (from);
  cout<<"Packet:"<<*packet<<" SIZE:"<<packet->GetSize()<<endl;
  packet->RemoveAllPacketTags ();
  packet->RemoveAllByteTags ();
  char buffer[1000];
  packet->CopyData((unsigned char*)buffer,packet->GetSize());
  InetSocketAddress address = InetSocketAddress::ConvertFrom (from);
  cout<<"Proxy server received " << packet->GetSize () << " bytes from " << address.GetIpv4 () << " Data:" <<buffer<<endl;
  string ca(buffer);
  ca=ca.substr(0,packet->GetSize());
  cout<<"The message received by proxy server is:"<<ca<<endl;
  string cb;
  reEncryption(ca,SK,Nb,cb);
  cout<<"The reencrypted message is:"<<cb<<endl;
  
  cout<<"Now the proxy server would sign this cipher text"<<cb<<endl;
  signKeyGen(Q,Xa,Ya,Alpha);

  string s1,s2,m;
  sign(Q,Ya,Xa,Alpha,s1,s2,m);
  cout<<"The signature generated is:"<<s1<<" "<<s2<<endl;
  string str=cb+"#"+s1+"#"+s2+"#"+m+"#";
  char data[1000];
  strcpy(data,str.c_str());
  cout<<"Message {Cipher+Signature sent to Destination is:"<<data<<endl;
  uint16_t dstport = 12345;
  Ipv4Address dstaddr ("10.0.0.2");
  mySendFunction(data, socket, dstaddr, dstport);
}

void dstSocketRecv (Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom (from);
  cout<<"Packet:"<<*packet<<" SIZE:"<<packet->GetSize()<<endl;
  packet->RemoveAllPacketTags ();
  packet->RemoveAllByteTags ();
  char buffer[1000];
  packet->CopyData((unsigned char*)buffer,packet->GetSize());
  InetSocketAddress address = InetSocketAddress::ConvertFrom (from);
  cout<<"Destination received " << packet->GetSize () << " bytes from " << address.GetIpv4 () << " Data:" <<buffer<<endl;
  string str(buffer);
  str=str.substr(0,packet->GetSize());
  stringstream tokenizer(str);
  string cb,s1,s2,m;
  getline(tokenizer,cb,'#');
  getline(tokenizer,s1,'#');
  getline(tokenizer,s2,'#');
  getline(tokenizer,m,'#');
  cout<<"B receive the tuple {Cb,s1,s2}"<<cb<<" "<<s1<<" "<<s2<<" "<<m<<endl;
  cout<<"Verifying the signature and the message"<<endl;
  string message;
  decrypt(cb,PRb,Nb,message);
  cout<<"The message decrypted by B is:"<<message<<endl;
  cout<<"Verify the signature now:"<<endl;
  validate(Q,Alpha,m,Ya,s1,s2);
  cout<<"End the processes"<<endl;
}

void dstSocketRecvMA(Ptr<Socket> socket)
{
  Address from;
  Ptr<Packet> packet = socket->RecvFrom (from);
  cout<<"Packet:"<<*packet<<" SIZE:"<<packet->GetSize()<<endl;
  packet->RemoveAllPacketTags ();
  packet->RemoveAllByteTags ();
  char buffer[1000];
  packet->CopyData((unsigned char*)buffer,packet->GetSize());
  InetSocketAddress address = InetSocketAddress::ConvertFrom (from);
  cout<<"Destination Received " << packet->GetSize () << " bytes from " << address.GetIpv4 () << " Data:" <<buffer<<endl;
  string c(buffer);
  c=c.substr(0,packet->GetSize());
  cout<<"The cipher text sent from A to B:"<<c<<endl;
  cout<<"Trying to decrypt using A's public key to verify it is A"<<endl;
  string m;
  decrypt(c,PKa,Na,m);
  cout<<"The message decrypted is:"<<m<<endl;
  string cb;
  encrypt(m,PRb,Nb,cb);
  cout<<"The encrypted cipher text by B to A is:"<<cb<<endl;
  char data[1000];
  strcpy(data,cb.c_str());
  socket->SetRecvCallback (MakeCallback (&dstSocketRecv));
  mySendFunction (data, socket, address.GetIpv4(), address.GetPort());
}

int main (int argc, char *argv[])
{
  
  keyGen(PRa,PKa,Na);
  keyGen(PRb,PKb,Nb);
  SharedKey(PKb,PRa,SK);


  cout<<"The keys of A are (PR,PK,N)"<<PRa<<" "<<PKa<<" "<<Na<<endl;
  cout<<"The keys of B are (PR,PK,N)"<<PRb<<" "<<PKb<<" "<<Nb<<endl;
  cout<<"The proxy re encryption key is:"<<SK<<endl;
  //cout<<"The shared key"<<SK<<endl;
  //now all the keys are initialized

 /*-------------KEYGEN END-----------------*/

  CommandLine cmd;
  cmd.Parse (argc, argv);
  
  Time::SetResolution (Time::NS);
  // LogComponentEnable ("UdpEchoClientApplication", LOG_LEVEL_INFO);
  // LogComponentEnable ("UdpEchoServerApplication", LOG_LEVEL_INFO);

  //Config::SetDefault("ns3::Ipv4GlobalRouting::RandomEcmpRouting",BooleanValue(ECMProuting));

  NodeContainer nodes;
  nodes.Create (3);

  PointToPointHelper pointToPoint;
  pointToPoint.SetDeviceAttribute ("DataRate", StringValue ("5Mbps"));
  pointToPoint.SetChannelAttribute ("Delay", StringValue ("2ms"));

  NetDeviceContainer dev1,dev2;
  dev1 = pointToPoint.Install (nodes.Get(0),nodes.Get(1));
  dev2 = pointToPoint.Install (nodes.Get(1),nodes.Get(2));

  InternetStackHelper stack;
  stack.Install (nodes);

  Ipv4AddressHelper address;
  address.SetBase ("10.1.1.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces = address.Assign (dev1);
  
  address.SetBase ("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer interfaces1 = address.Assign (dev2);

  Ipv4GlobalRoutingHelper:: PopulateRoutingTables();


  Ptr<Socket> srcSocket = Socket::CreateSocket (nodes.Get(0), TypeId::LookupByName ("ns3::UdpSocketFactory"));
  uint16_t srcport = 12350;
  Ipv4Address srcaddr ("10.1.1.1");
  InetSocketAddress src = InetSocketAddress (srcaddr, srcport);
  srcSocket->Bind (src);
  srcSocket->SetRecvCallback (MakeCallback (&srcSocketRecvMA));

  Ptr<Socket> midSocket = Socket::CreateSocket (nodes.Get(1), TypeId::LookupByName ("ns3::UdpSocketFactory"));
  uint16_t midport = 12348;
  Ipv4Address midaddr ("10.0.0.1");
  InetSocketAddress mid = InetSocketAddress (midaddr, midport);
  midSocket->Bind (mid);
  midSocket->SetRecvCallback (MakeCallback (&midSocketRecv));

  Ptr<Socket> dstSocket = Socket::CreateSocket (nodes.Get(2), TypeId::LookupByName ("ns3::UdpSocketFactory"));
  uint16_t dstport = 12345;
  Ipv4Address dstaddr ("10.0.0.2");
  InetSocketAddress dst = InetSocketAddress (dstaddr, dstport);
  dstSocket->Bind (dst);
  dstSocket->SetRecvCallback (MakeCallback (&dstSocketRecvMA));

  
  //first step is achieving mutual authentication between A and B
  cout<<"Mutual Authentication between A and B"<<endl;
  authenticationMessage="9";
  string c;
  encrypt(authenticationMessage,PRa,Na,c);// message is encrypted using the private key of A

  char data[1000];
  strcpy(data,c.c_str());
  
  cout<<"The data being sent is:"<<data<<endl;
  Packet::EnablePrinting();


  AnimationInterface anim ("EndLab.xml");
  anim.SetConstantPosition (nodes.Get(0), 1.0, 10.0);
  anim.SetConstantPosition (nodes.Get(1), 8.0, 30.0);
  anim.SetConstantPosition (nodes.Get(2), 15.0, 70.0);

  Simulator::Schedule (Seconds (1),&mySendFunction, data, srcSocket, dstaddr, dstport);

  Simulator::Run ();
  Simulator::Destroy ();
  return 0;
}
