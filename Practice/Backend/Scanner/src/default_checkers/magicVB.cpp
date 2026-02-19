#include "../../include/default_checkers/magicVB.hpp"

#include <string>

std::string magicTypeVB(const std::vector<unsigned char>& buffer)
{
    if (buffer.size() < 4)
    {
        return "unknown";
    }

    unsigned char b0VB = buffer[0];
    unsigned char b1VB = buffer[1];
    unsigned char b2VB = buffer[2];
    unsigned char b3VB = buffer[3];

    if (b0VB == 0x50 && b1VB == 0x4B && (b2VB == 0x03 || b2VB == 0x05 || b2VB == 0x07)) 
        return "zip";

    if (buffer.size() >= 8 &&
        b0VB == 0xD0 && b1VB == 0xCF && b2VB == 0x11 && b3VB == 0xE0 &&
        buffer[4] == 0xA1 && buffer[5] == 0xB1 && buffer[6] == 0x1A && buffer[7] == 0xE1)
    {
        return "ole";
    }

    if (b0VB == 0x89 && b1VB == 0x50 && b2VB == 0x4E && b3VB == 0x47)
        return "png";

    if (b0VB == 0xFF && b1VB == 0xD8)
        return "jpg";

    if (b0VB == 0x47 && b1VB == 0x49 && b2VB == 0x46 && b3VB == 0x38)
        return "gif";

    if (b0VB == 0x42 && b1VB == 0x4D)
        return "bmp";

    if (b0VB == '%' && b1VB == 'P' && b2VB == 'D' && b3VB == 'F')
        return "pdf";

    if (b0VB == 0x4D && b1VB == 0x5A)
        return "pe";

    return "unknown";
}