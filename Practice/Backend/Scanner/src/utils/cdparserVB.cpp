#include "../../include/utils/cdparserVB.hpp"

#include "../../include/utils/endian_leVB.hpp"
#include "../../include/utils/to_lowerVB.hpp"


bool parseCDVB(const std::vector<unsigned char>& buffer, std::vector<ZipNameVB>& out, std::uint16_t& declaredTotalEntries, bool& zip64Possible)
{
    out.clear();
    declaredTotalEntries = 0;
    zip64Possible = false;

    const std::size_t minEOCD = 22;

    if (buffer.size() < minEOCD)
        return false;

    const std::size_t maxComment = 0xFFFF;
    const std::size_t scanStart = (buffer.size() > (minEOCD + maxComment))
            ? (buffer.size() - (minEOCD + maxComment)): 0;

    std::size_t eocdPos = static_cast<std::size_t>(-1);

    for (std::size_t i = buffer.size() - minEOCD; ; --i)
    {
        if (buffer[i] == 0x50 && buffer[i + 1] == 0x4B &&
            buffer[i + 2] == 0x05 && buffer[i + 3] == 0x06)
        {
            eocdPos = i;
            break;
        }

        if (i == scanStart)
            break;
    }

    if (eocdPos == static_cast<std::size_t>(-1))
        return false;

    std::uint16_t totalEntries = 0;
    std::uint32_t cdSize = 0;
    std::uint32_t cdOffset = 0;

    if (!readU16LEVB(buffer, eocdPos + 10, totalEntries))
        return false;

    if (!readU32LEVB(buffer, eocdPos + 12, cdSize))
        return false;

    if (!readU32LEVB(buffer, eocdPos + 16, cdOffset))
        return false;

    declaredTotalEntries = totalEntries;

    if (totalEntries == 0xFFFF || cdSize == 0xFFFFFFFFu || cdOffset == 0xFFFFFFFFu)
    {
        zip64Possible = true;
        return false;
    }

    const std::size_t cdOff = static_cast<std::size_t>(cdOffset);
    const std::size_t cdEnd = cdOff + static_cast<std::size_t>(cdSize);

    if (cdOff >= buffer.size() || cdEnd > buffer.size() || cdEnd < cdOff)
        return false;

    const std::size_t MAX_ENTRIES = 5000;

    std::size_t p = cdOff;

    while (p + 46 <= cdEnd && out.size() < MAX_ENTRIES)
    {
        if (!(buffer[p] == 0x50 && buffer[p + 1] == 0x4B && buffer[p + 2] == 0x01 && buffer[p + 3] == 0x02))
            return false;

        std::uint16_t nameLen = 0;
        std::uint16_t extraLen = 0;
        std::uint16_t commentLen = 0;

        if (!readU16LEVB(buffer, p + 28, nameLen))
            return false;

        if (!readU16LEVB(buffer, p + 30, extraLen))
            return false;

        if (!readU16LEVB(buffer, p + 32, commentLen))
            return false;

        const std::size_t namePos = p + 46;
        const std::size_t next =
            namePos +
            static_cast<std::size_t>(nameLen) +
            static_cast<std::size_t>(extraLen) +
            static_cast<std::size_t>(commentLen);

        if (next > cdEnd || next <= p)
            return false;

        std::string name(reinterpret_cast<const char*>(&buffer[namePos]), reinterpret_cast<const char*>(&buffer[namePos + nameLen]));

        toLowerVB(name);

        ZipNameVB e;
        e.name = std::move(name);
        out.push_back(std::move(e));

        p = next;
    }

    return !out.empty();
}