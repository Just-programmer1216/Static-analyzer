#include "../../include/utils/buffer_searchVB.hpp"
#include "../../include/utils/to_lowerVB.hpp"

#include <algorithm>

bool bufferSearchVB(const std::vector<unsigned char>& buffer, const std::string& pattern)
{
    if (pattern.empty() || buffer.size() < pattern.size())
        return false;

    return std::search(buffer.begin(), buffer.end(), pattern.begin(), pattern.end(),
        [](unsigned char a, unsigned char b)
        {return toLowerByteVB(a) == toLowerByteVB(static_cast<unsigned char>(b));}
    ) != buffer.end();
}
