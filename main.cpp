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
//	const pcpp::IPv6HopByHopHeader newhopheader({ pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder(HBHType, HBHValue, HBHValue_Len)});//���캯������
//	iplayer->addExtension<pcpp::IPv6HopByHopHeader>(newhopheader);
//}


int main(int argc, char* argv[])
{
	//���ݰ���ȡ open a pcap file for reading
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

	uint8_t HBHType = 5;//����
	uint8_t HBHValue_Len = 2;//�����ֽ���

	//const uint8_t* HBHValue = &value;//��ָ�ĵ�ַֻ��

	//TLV��������
	uint8_t HBHValue[2];
	HBHValue[0] = 0x12;
	HBHValue[1] = 0x34;
	/*uint16_t val = htons(0xACBD);//htons�ǽ����ͱ����������ֽ�˳��ת��������ֽ�˳�򣬾��������ڵ�ַ�ռ�洢��ʽ��Ϊ��λ�ֽڴ�����ڴ�ĵ͵�ַ����
	memcpy(&HBHValue, &val, sizeof(uint16_t));*/


	//�������
	pcpp::RawPacketVector resultHBH;
	std::string outputFile = "addHBH.pcap";
	pcpp::IFileWriterDevice* writer = nullptr;//����
	writer = new pcpp::PcapFileWriterDevice(outputFile, reader.getLinkLayerType());//����

	if (!writer->open())
	{
		EXIT_WITH_ERROR("Error opening output file");
	}

	//���ݰ����� parse the raw packet into a parsed packet������ΪparsedPacket
	pcpp::Packet parsedPacket(&rawPacket);

	pcpp::IPv6Layer* iplayer = nullptr;//IPv6��ָ��
	iplayer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();//�ӽ��������ݰ��л�ȡIPv6���ַiplayer��ʹ��ָ��parsedPacket


	//���������ݰ�����������½������ݰ�ָ��ΪnewHBH
	pcpp::RawPacket* newHBHRawPacket = new pcpp::RawPacket(*parsedPacket.getRawPacket());
	pcpp::Packet newHBH(newHBHRawPacket);
	pcpp::IPv6Layer* HBHiplayer = nullptr;//�����ݰ���IPv6��ָ��HBHiplayer
	HBHiplayer = newHBH.getLayerOfType<pcpp::IPv6Layer>();//�ӽ��������ݰ��л�ȡIPv6���ַ��ʹ��ָ��newHBH��IPv6ָ��ΪHBHiplayer

	//����TLVѡ������
	std::vector<pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder> myTLV;
	pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder myHBHTLVoption(HBHType, HBHValue, HBHValue_Len);
	//����padN���
	pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder padN((uint8_t)1, NULL, (uint8_t)0);
	//��������
	myTLV.push_back(myHBHTLVoption);
	myTLV.push_back(padN);

	//const pcpp::IPv6HopByHopHeader newhopheader({ pcpp::IPv6TLVOptionHeader::IPv6TLVOptionBuilder((uint8_t)0, HBHValue, (uint8_t)6) });//���캯������
	
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


	//��������ݰ�IP�㹹������չͷ
	HBHiplayer->addExtension<pcpp::IPv6HopByHopHeader>(newhopheader);
	newHBH.computeCalculateFields();
	
	//ѹ���������
	resultHBH.pushBack(newHBH.getRawPacket());
	//writer���
	writer->writePackets(resultHBH);

	std::cout << newhopheader.getExtensionType() << std::endl;
	

	// close the file
	reader.close();
	delete writer;

	return 0;
}
