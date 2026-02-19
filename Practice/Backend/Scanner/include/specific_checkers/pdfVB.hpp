#ifndef PDF_VB_HPP
#define PDF_VB_HPP

#include <vector>
#include "../file_infoVB.hpp"
#include "../json.hpp"

using json = nlohmann::json;

json checkPdfVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer);

#endif
