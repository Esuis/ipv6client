#include <iostream>
#include <IPv6Layer.h>
#include <Packet.h>
#include <PcapFileDevice.h>


#define EXIT_WITH_ERROR(reason) do { \
	std::cout << std::endl << "ERROR: " << reason << std::endl << std::endl; \
	exit(1); \
	} while(0)

//void setHBHheader(pcpp::IPv6Layer* iplayer, uint8_t HBHType, uint8_t HBHValue_Len, const uint8_t* HBHValue) 
//{
//	const pcpp::IPv6HopByHopHeader newhopheader({ pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder(HBHType, HBHValue, HBHValue_Len)});//构造函数重载
//	iplayer->addExtension<pcpp::IPv6HopByHopHeader>(newhopheader);
//}


int main(int argc, char* argv[])
{
	//数据包读取 open a pcap file for reading
	pcpp::PcapFileReaderDevice reader("1.pcap");
	if (!reader.open())
	{
		std::cerr << "Error opening the pcap file" << std::endl;
		return 1;
	}

	// read the first (and only) packet from the file
	pcpp::RawPacket rawPacket;
	if (!reader.getNextPacket(rawPacket))
	{
		std::cerr << "Couldn't read the first packet in the file" << std::endl;
		return 1;
	}



	//uint8_t value = 0xBB;//0b1100011100000111

	uint8_t HBHType = 5;//类型
	uint8_t HBHValue_Len = 2;//数据字节数

	//const uint8_t* HBHValue = &value;//所指的地址只读

	//TLV数据输入
	uint8_t HBHValue[2];
	HBHValue[0] = 0x12;
	HBHValue[1] = 0x34;
	/*uint16_t val = htons(0xACBD);//htons是将整型变量从主机字节顺序转变成网络字节顺序，就是整数在地址空间存储方式变为高位字节存放在内存的低地址处。
	memcpy(&HBHValue, &val, sizeof(uint16_t));*/


	//输出向量
	pcpp::RawPacketVector resultHBH;
	std::string outputFile = "addHBH.pcap";
	pcpp::IFileWriterDevice* writer = nullptr;//父类
	writer = new pcpp::PcapFileWriterDevice(outputFile, reader.getLinkLayerType());//子类

	if (!writer->open())
	{
		EXIT_WITH_ERROR("Error opening output file");
	}

	//数据包解析 parse the raw packet into a parsed packet，变量为parsedPacket
	pcpp::Packet parsedPacket(&rawPacket);

	pcpp::IPv6Layer* iplayer = nullptr;//IPv6层指针
	iplayer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();//从解析的数据包中获取IPv6层地址iplayer，使用指针parsedPacket


	//创建新数据包用于输出，新解析数据包指针为newHBH
	pcpp::RawPacket* newHBHRawPacket = new pcpp::RawPacket(*parsedPacket.getRawPacket());
	pcpp::Packet newHBH(newHBHRawPacket);
	pcpp::IPv6Layer* HBHiplayer = nullptr;//新数据包的IPv6层指针HBHiplayer
	HBHiplayer = newHBH.getLayerOfType<pcpp::IPv6Layer>();//从解析的数据包中获取IPv6层地址，使用指针newHBH，IPv6指针为HBHiplayer

	//定义TLV选项向量
	std::vector<pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder> myTLV;
	pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder myHBHTLVoption(HBHType, HBHValue, HBHValue_Len);
	//定义padN填充
	pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder padN((uint8_t)1, NULL, (uint8_t)0);
	//填入向量
	myTLV.push_back(myHBHTLVoption);
	myTLV.push_back(padN);

	//const pcpp::IPv6HopByHopHeader newhopheader({ pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder((uint8_t)0, HBHValue, (uint8_t)6) });//构造函数重载
	
	const pcpp::IPv6HopByHopHeader newhopheader(myTLV);

	//// verify the packet is IPv63
	//if (parsedPacket.isPacketOfType(pcpp::IPv6))
	//{
	//	// extract source and dest IPs
	//	pcpp::IPv6Address srcIP = parsedPacket.getLayerOfType<pcpp::IPv6Layer>()->getSrcIPv6Address();
	//	pcpp::IPv6Address destIP = parsedPacket.getLayerOfType<pcpp::IPv6Layer>()->getDstIPv6Address();
	//	
	//	// print source and dest IPs
	//	std::cout
	//		<< "Source IP is '" << srcIP << "'; "
	//		<< "Dest IP is '" << destIP << "'"
	//		<< std::endl;
	//}


	//在输出数据包IP层构建新扩展头
	HBHiplayer->addExtension<pcpp::IPv6HopByHopHeader>(newhopheader);
	newHBH.computeCalculateFields();
	
	//压入输出向量
	resultHBH.pushBack(newHBH.getRawPacket());
	//writer输出
	writer->writePackets(resultHBH);

	std::cout << newhopheader.getExtensionType() << std::endl;
	

	// close the file
	reader.close();
	delete writer;

	return 0;
}
