#ifndef TEXT_SCRIPT_VB_HPP
#define TEXT_SCRIPT_VB_HPP

#include <vector>
#include "../file_infoVB.hpp"
#include "../json.hpp"


using json = nlohmann::json;

json checkScriptVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer, bool& scriptHint);

#endif
