#include "../../include/utils/endian_leVB.hpp"

bool readU16LEVB(const std::vector<unsigned char>& buffer, std::size_t offset, std::uint16_t& out)
{
    if (offset + 2 > buffer.size())
        return false;

    out = static_cast<std::uint16_t>(buffer[offset] | (static_cast<std::uint16_t>(buffer[offset + 1]) << 8));

    return true;
}

bool readU32LEVB(const std::vector<unsigned char>& buffer, std::size_t offset, std::uint32_t& out)
{
    if (offset + 4 > buffer.size())
        return false;

    out = static_cast<std::uint32_t>(buffer[offset] | (static_cast<std::uint32_t>(buffer[offset + 1]) << 8) | (static_cast<std::uint32_t>(buffer[offset + 2]) << 16) | (static_cast<std::uint32_t>(buffer[offset + 3]) << 24));

    return true;
}
