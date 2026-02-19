#ifndef EXT_MISMATCH_VB_HPP
#define EXT_MISMATCH_VB_HPP

#include "../file_infoVB.hpp"
#include "../json.hpp"

using json = nlohmann::json;


json checkExtMismatchVB(const FileInfoVB& info);

#endif
