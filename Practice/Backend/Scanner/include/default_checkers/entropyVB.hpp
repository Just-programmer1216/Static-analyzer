#ifndef ENTROPY_VB_HPP
#define ENTROPY_VB_HPP

#include <vector>
#include "../file_infoVB.hpp"
#include "../json.hpp"

using json = nlohmann::json;
double calcEntropyRangeVB(const std::vector<unsigned char>& buffer, std::size_t offset, std::size_t length);
json checkEntropyVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer);

#endif