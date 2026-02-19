 #ifndef IMAGE_VB_HPP
#define IMAGE_VB_HPP

#include <vector>
#include "../file_infoVB.hpp"
#include "../json.hpp"

using json = nlohmann::json;

json checkImageVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer);

#endif