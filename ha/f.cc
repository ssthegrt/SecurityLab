#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include "ns3/netanim-module.h"
#include "ns3/ipv4-global-routing-helper.h"
#include "rsa.cpp"

using namespace ns3;

string publicKey,privateKey;
string publicKey1,privateKey1;

NS_LOG_COMPONENT_DEFINE ("SocketBoundRoutingExample");

void Send (char *data,Ptr<Socket> sock, Ipv4Address dstaddr, uint16_t port)
{
  Ptr<Packet> p = Create<Packet> ();
  uint8_t buffer[1000];
  bzero((char*)buffer,100);
  uint32_t size;
  strcpy((char*)buffer,data);
  size = strlen((char*)buffer);
  Ptr<Packet> p1 = Create<Packet> (buffer,size);
  p->AddAtEnd(p1);
  sock->SendTo (p, 0, InetSocketAddress (dstaddr,port));
  return;
}

void recv (Ptr<Socket> socket)
{
  Address from;

  Ptr<Packet> packet = socket->RecvFrom (from);
  cout<<"Packet:"<<*packet<<endl;
  packet->RemoveAllPacketTags ();
  packet->RemoveAllByteTags ();
  unsigned char buffer[1000];
  packet->CopyData(buffer,1000);
  string msg = string((char*)buffer);
  string msg1="";
  for(unsigned int i=0;i<msg.length();i++)
  {
  	if(msg[i]>=48&&msg[i]<=57)
  	{
  		msg1=msg1+msg[i];
  	}
  	else
  	{
  		break;
  	}
  }
  string message = decrypt((char*)msg1.c_str(),privateKey);
  string message1 = decrypt((char*)message.c_str(),publicKey1);
  cout<<"Decrypting...."<<endl;
  cout<<"Message: "<<message1<<endl;
}

int main (int argc, char *argv[])
{
  
  
  key_gen(publicKey,privateKey,101910191019101);
  
  key_gen(publicKey1,privateKey1,1019101910191013);
  cout<<"Public Key: "<<publicKey<<"\tPrivate Key: "<<privateKey<<endl;
  cout<<"Public Key1: "<<publicKey1<<"\tPrivate Key: "<<privateKey1<<endl;
  string Message = "111";
  string Cipher = encrypt((char*)Message.c_str(),publicKey);
  cout<<"CIPHER:: "<<Cipher<<endl;
  string PlainText = decrypt((char*)Cipher.c_str(),privateKey);
  cout<<"PlainText::: "<<PlainText<<endl;

 /*-------------KEYGEN END-----------------*/

  CommandLine cmd;
  cmd.Parse (argc, argv);
  
  Time::SetResolution (Time::NS);
 
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
  srcSocket->Bind ();
  srcSocket->SetRecvCallback (MakeCallback (&recv));

  Ptr<Socket> dstSocket = Socket::CreateSocket (nodes.Get(2), TypeId::LookupByName ("ns3::UdpSocketFactory"));
  uint16_t dstport = 12345;
  Ipv4Address dstaddr ("10.0.0.2");
  InetSocketAddress dst = InetSocketAddress (dstaddr, dstport);
  dstSocket->Bind (dst);
  dstSocket->SetRecvCallback (MakeCallback (&recv));
//Maintaining Confidentiality and Authentication
  char data[1000];
  strcpy(data,"310198");
  string authenticated=encrypt(data,privateKey1);
  string integratedMessage=encrypt((char*)authenticated.c_str(),publicKey);
  
   
  Packet::EnablePrinting();

  Simulator::Schedule (Seconds (1),&Send,(char*)integratedMessage.c_str(), srcSocket, dstaddr, dstport);

  Simulator::Run ();
  Simulator::Destroy ();
  return 0;
}
