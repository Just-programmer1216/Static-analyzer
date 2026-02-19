#include "../../include/specific_checkers/imageVB.hpp"

#include "../../include/utils/addingVB.hpp"
#include "../../include/utils/endian_leVB.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

static void hugeVB(json& meta, json& signals, std::uint32_t w, std::uint32_t h)
{
    meta["width"] = w;
    meta["height"] = h;

    bool overflow = false;
    std::uint32_t pixels = 0;

    if (h != 0 && w > (std::numeric_limits<std::uint32_t>::max() / h))
    {
        overflow = true;
        pixels = std::numeric_limits<std::uint32_t>::max();
    }
    else
        pixels = w * h;

    meta["pixels"] = pixels;
    meta["pixels_overflow"] = overflow;

    if (w > 30000ULL || h > 30000ULL || overflow || pixels > 100000000ULL)
        addingVB(signals, "structure_warning", "huge_dimensions", 6);
}

static void overlayVB(json& meta, json& signals, const std::vector<unsigned char>& buffer, std::size_t endPos)
{
    std::size_t overlaySize = 0;

    if (endPos < buffer.size())
        overlaySize = static_cast<std::size_t>(buffer.size() - endPos);

    meta["overlay_present"] = (overlaySize > 0);
    meta["overlay_size"] = overlaySize;

    if (overlaySize > 0)
        addingVB(signals, "embedded_data", "data_after_image_end", 6);
}

static bool readU16BEVB(const std::vector<unsigned char>& b, std::size_t off, std::uint16_t& out)
{
    if (off + 2 > b.size())
        return false;

    out = static_cast<std::uint16_t>((static_cast<std::uint16_t>(b[off]) << 8) | (static_cast<std::uint16_t>(b[off + 1])));
    return true;
}

static bool readU32BEVB(const std::vector<unsigned char>& b, std::size_t off, std::uint32_t& out)
{
    if (off + 4 > b.size())
        return false;

    out = (static_cast<std::uint32_t>(b[off]) << 24) | (static_cast<std::uint32_t>(b[off + 1]) << 16) | (static_cast<std::uint32_t>(b[off + 2]) << 8) | (static_cast<std::uint32_t>(b[off + 3]));
    return true;
}

static json checkPngVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer)
{
    json result;
    json meta;
    json signals = json::array();

    result["type"] = info.magicType;


    if (buffer.size() < 8 + 4 + 4 + 13 + 4)// signature + length + type + IHDR + CRC
    {
        addingVB(signals, "structure_warning", "png_too_small", 8);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    std::uint32_t len = 0;
    std::uint32_t w = 0;
    std::uint32_t h = 0;

    if (!readU32BEVB(buffer, 8, len))
        len = 0;

    const std::string type(reinterpret_cast<const char*>(&buffer[12]), reinterpret_cast<const char*>(&buffer[16]));

    if (type != "IHDR" || len < 13)
        addingVB(signals, "structure_warning", "png_missing_ihdr", 8);
    else
    {
        readU32BEVB(buffer, 16, w);
        readU32BEVB(buffer, 20, h);
        hugeVB(meta, signals, w, h);
    }

    bool hasIEND = false;
    std::size_t iendEnd = buffer.size();

    if (buffer.size() >= 12)
    {
        std::size_t scanFrom = 8;
        if (buffer.size() > 4096)
            scanFrom = buffer.size() - 4096;
        if (scanFrom < 8)
            scanFrom = 8;

        std::size_t i = buffer.size() - 12;
        for (;;)
        {
            if (i < scanFrom)
                break;

            if (buffer[i + 4] == 'I' && buffer[i + 5] == 'E' &&
                buffer[i + 6] == 'N' && buffer[i + 7] == 'D')
            {
                std::uint32_t l = 1;
                if (readU32BEVB(buffer, i, l) && l == 0)
                {
                    hasIEND = true;
                    iendEnd = i + 12;
                    break;
                }
            }

            if (i == 0)
                break;
            --i;
        }
    }

    meta["has_iend"] = hasIEND;

    if (!hasIEND)
        addingVB(signals, "structure_warning", "png_missing_iend", 6);
    else
        overlayVB(meta, signals, buffer, iendEnd);

    result["meta"] = meta;
    result["signals"] = signals;
    return result;
}

static json checkJpegVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer)
{
    json result;
    json meta;
    json signals = json::array();

    result["type"] = info.magicType;

    bool hasEOI = false;
    std::size_t eoiEnd = buffer.size();

    std::size_t scanTail = 2;
    if (buffer.size() > 4096)
        scanTail = buffer.size() - 4096;

    if (buffer.size() >= 2)
    {
        std::size_t i = buffer.size() - 2;
        for (;;)
        {
            if (i < scanTail)
                break;

            if (buffer[i] == 0xFF && buffer[i + 1] == 0xD9)
            {
                hasEOI = true;
                eoiEnd = i + 2;
                break;
            }

            if (i == 0)
                break;

            --i;
        }
    }

    meta["has_eoi"] = hasEOI;

    if (!hasEOI)
        addingVB(signals, "structure_warning", "jpeg_missing_eoi", 6);
    else
        overlayVB(meta, signals, buffer, eoiEnd);

    bool dimFound = false;
    std::uint16_t w = 0;
    std::uint16_t h = 0;

    std::size_t pos = 2;
    const std::size_t limit = std::min<std::size_t>(buffer.size(), 512ULL * 1024ULL);

    while (pos + 9 < limit)
    {
        if (buffer[pos] != 0xFF)
        {
            pos++;
            continue;
        }

        while (pos < limit && buffer[pos] == 0xFF)
            pos++;

        if (pos >= limit)
            break;

        const unsigned char marker = buffer[pos];
        pos++;

        if (marker == 0xD9 || marker == 0xDA)
            break;

        if ((marker >= 0xD0 && marker <= 0xD7) || marker == 0x01)
            continue;

        std::uint16_t segLen = 0;
        if (!readU16BEVB(buffer, pos, segLen) || segLen < 2)
            break;

        if (pos + segLen > limit)
            break;

        if ((marker >= 0xC0 && marker <= 0xCF) && marker != 0xC4 && marker != 0xC8 && marker != 0xCC)
        {
            readU16BEVB(buffer, pos + 3, h);
            readU16BEVB(buffer, pos + 5, w);
            dimFound = true;
            hugeVB(meta, signals, w, h);
            break;
        }

        pos += static_cast<std::size_t>(segLen);
    }

    meta["dimensions_found"] = dimFound;
    if (!dimFound)
        addingVB(signals, "structure_warning", "jpeg_no_sof_found", 4);

    result["meta"] = meta;
    result["signals"] = signals;
    return result;
}

static json checkGifVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer)
{
    json result;
    json meta;
    json signals = json::array();

    result["type"] = info.magicType;

    if (buffer.size() < 13)
    {
        addingVB(signals, "structure_warning", "gif_too_small", 8);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    std::uint16_t w = 0;
    std::uint16_t h = 0;
    readU16LEVB(buffer, 6, w);
    readU16LEVB(buffer, 8, h);

    hugeVB(meta, signals, w, h);

    bool hasTrailer = false;
    std::size_t trailerEnd = buffer.size();

    std::size_t scanTail = 13;
    if (buffer.size() > 4096)
        scanTail = buffer.size() - 4096;

    if (!buffer.empty())
    {
        std::size_t i = buffer.size() - 1;
        for (;;)
        {
            if (i < scanTail)
                break;

            if (buffer[i] == 0x3B)
            {
                hasTrailer = true;
                trailerEnd = i + 1;
                break;
            }

            if (i == 0)
                break;

            --i;
        }
    }

    meta["has_trailer"] = hasTrailer;

    if (!hasTrailer)
        addingVB(signals, "structure_warning", "gif_missing_trailer", 6);
    else
        overlayVB(meta, signals, buffer, trailerEnd);

    result["meta"] = meta;
    result["signals"] = signals;
    return result;
}

static json checkBmpVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer)
{
    json result;
    json meta;
    json signals = json::array();

    result["type"] = info.magicType;

    std::uint32_t pixelOffset = 0;
    std::uint32_t dibSize = 0;

    if (!readU32LEVB(buffer, 10, pixelOffset) || !readU32LEVB(buffer, 14, dibSize))
    {
        addingVB(signals, "structure_warning", "bmp_header_oob", 8);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    if (dibSize < 40 || 14 + static_cast<std::size_t>(dibSize) > buffer.size())
    {
        addingVB(signals, "structure_warning", "bmp_dib_oob", 8);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    std::uint32_t wu = 0;
    std::uint32_t hu = 0;

    const std::int32_t wi = static_cast<std::int32_t>(wu);
    const std::int32_t hi = static_cast<std::int32_t>(hu);

    const std::uint32_t w = (wi < 0) ? static_cast<std::uint32_t>(-static_cast<std::int64_t>(wi)) : static_cast<std::uint32_t>(wi);
    const std::uint32_t h = (hi < 0) ? static_cast<std::uint32_t>(-static_cast<std::int64_t>(hi)) : static_cast<std::uint32_t>(hi);

    hugeVB(meta, signals, w, h);

    meta["pixel_offset"] = pixelOffset;

    if (pixelOffset >= buffer.size())
        addingVB(signals, "structure_warning", "bmp_pixel_offset_oob", 6);

    result["meta"] = meta;
    result["signals"] = signals;
    return result;
}

json checkImageVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer)
{
    if (info.magicType == "png")
        return checkPngVB(info, buffer);

    if (info.magicType == "jpg")
        return checkJpegVB(info, buffer);

    if (info.magicType == "gif")
        return checkGifVB(info, buffer);

    if (info.magicType == "bmp")
        return checkBmpVB(info, buffer);

    json result;
    json meta;
    json signals = json::array();

    result["type"] = info.magicType;

    result["meta"] = meta;
    result["signals"] = signals;
    return result;
}