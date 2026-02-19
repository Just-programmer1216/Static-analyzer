#ifndef PE_VB_HPP
#define PE_VB_HPP

#include <vector>
#include "../file_infoVB.hpp"
#include "../json.hpp"

using json = nlohmann::json;

json checkPeVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer);

#endif