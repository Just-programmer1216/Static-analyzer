#ifndef MAGIC_VB_HPP
#define MAGIC_VB_HPP

#include <vector>
#include "../json.hpp"

using json = nlohmann::json;

std::string magicTypeVB(const std::vector<unsigned char>& buffer);

#endif