#ifndef OFFICE_VB_HPP
#define OFFICE_VB_HPP

#include <vector>
#include "../file_infoVB.hpp"
#include "../json.hpp"


using json = nlohmann::json;

json checkOfficeVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer);

#endif
