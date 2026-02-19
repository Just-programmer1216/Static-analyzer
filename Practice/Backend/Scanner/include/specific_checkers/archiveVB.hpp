#ifndef ARCHIVE_VB_HPP
#define ARCHIVE_VB_HPP

#include <vector>
#include "../file_infoVB.hpp"
#include "../json.hpp"

using json = nlohmann::json;

json checkArchiveVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer);

#endif