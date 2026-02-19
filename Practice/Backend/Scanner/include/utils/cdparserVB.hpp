#ifndef CD_PARSER_VB_HPP
#define CD_PARSER_VB_HPP

#include <cstdint>
#include <string>
#include <vector>


struct ZipNameVB
{
    std::string name;
};

bool parseCDVB(const std::vector<unsigned char>& buffer, std::vector<ZipNameVB>& out, std::uint16_t& declaredTotalEntries, bool& zip64Possible);

#endif