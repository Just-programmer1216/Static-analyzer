#include "../../include/utils/to_lowerVB.hpp"

#include <algorithm>
#include <cctype>

void toLowerVB(std::string& s)
{
    std::transform( s.begin(), s.end(), s.begin(),
    [](unsigned char c)
    { return static_cast<char>(std::tolower(c)); });
}

unsigned char toLowerByteVB(unsigned char c)
{
    if (c >= 'A' && c <= 'Z')
        return static_cast<unsigned char>(c + ('a' - 'A'));

    return c;
}