#include "../../include/specific_checkers/peVB.hpp"

#include "../../include/utils/endian_leVB.hpp"
#include "../../include/utils/addingVB.hpp"
#include "../../include/utils/to_lowerVB.hpp"
#include "../../include/default_checkers/entropyVB.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

static constexpr std::uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000u;
static constexpr std::uint32_t IMAGE_SCN_MEM_READ    = 0x40000000u;
static constexpr std::uint32_t IMAGE_SCN_MEM_WRITE   = 0x80000000u;

static bool inRangeVB(const std::vector<unsigned char>& b, std::size_t off, std::size_t n)
{
    return off <= b.size() && n <= b.size() - off;
}

static bool readBytesVB(const std::vector<unsigned char>& b, std::size_t off, void* out, std::size_t n)
{
    if (!inRangeVB(b, off, n))
        return false;

    std::memcpy(out, &b[off], n);
    return true;
}

static bool readCStringVB(const std::vector<unsigned char>& b, std::size_t off, std::string& out, std::size_t maxLen = 260)
{
    out.clear();

    if (off >= b.size())
        return false;

    for (std::size_t i = off; i < b.size() && out.size() < maxLen; ++i)
    {
        unsigned char c = b[i];
        if (c == 0)
            return true;

        if (c >= 0x20 && c <= 0x7E)
            out.push_back(static_cast<char>(c));
        else
            break;
    }

    return !out.empty();
}

struct PeSectionVB
{
    std::string   name;
    std::uint32_t vaddr;
    std::uint32_t vsize;
    std::uint32_t rawPtr;
    std::uint32_t rawSize;
    std::uint32_t characteristics;
};

static bool isRWXVB(std::uint32_t ch)
{
    return (ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_READ) && (ch & IMAGE_SCN_MEM_WRITE);
}

static bool isWXVB(std::uint32_t ch)
{
    return (ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE);
}

static bool hasExecVB(std::uint32_t ch)
{
    return (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
}

static bool rvaToOffsetVB(const std::vector<PeSectionVB>& secs, std::uint32_t rva, std::uint32_t& outOff)
{
    for (const auto& s : secs)
    {
        const std::uint32_t start = s.vaddr;
        const std::uint32_t end   = start + std::max(s.vsize, s.rawSize);

        if (rva >= start && rva < end)
        {
            outOff = s.rawPtr + (rva - start);
            return true;
        }
    }

    return false;
}

static bool parseImportsVB(const std::vector<unsigned char>& buffer, const std::vector<PeSectionVB>& secs, std::uint32_t importRva, std::uint32_t importSize, std::vector<std::string>& outDlls)
{
    outDlls.clear();

    if (importRva == 0 || importSize == 0)
        return true;

    std::uint32_t impOff = 0;
    if (!rvaToOffsetVB(secs, importRva, impOff))
        return false;

    const std::size_t maxDesc = 4096;
    std::size_t count = 0;

    for (;;)
    {
        if (count++ > maxDesc)
            return false;

        if (!inRangeVB(buffer, static_cast<std::size_t>(impOff), 20))
            break;

        std::uint32_t origThunk = 0;
        std::uint32_t timeDate  = 0;
        std::uint32_t fwdChain  = 0;
        std::uint32_t nameRva   = 0;
        std::uint32_t firstThunk= 0;

        if (!readU32LEVB(buffer, impOff + 0, origThunk))   return false;
        if (!readU32LEVB(buffer, impOff + 4, timeDate))    return false;
        if (!readU32LEVB(buffer, impOff + 8, fwdChain))    return false;
        if (!readU32LEVB(buffer, impOff + 12, nameRva))    return false;
        if (!readU32LEVB(buffer, impOff + 16, firstThunk)) return false;

        if (origThunk == 0 && timeDate == 0 && fwdChain == 0 && nameRva == 0 && firstThunk == 0)
            break;

        std::uint32_t nameOff = 0;
        if (rvaToOffsetVB(secs, nameRva, nameOff))
        {
            std::string dll;
            if (readCStringVB(buffer, nameOff, dll, 260))
            {
                toLowerVB(dll);
                outDlls.push_back(dll);
            }
        }

        impOff += 20;
    }

    std::sort(outDlls.begin(), outDlls.end());
    outDlls.erase(std::unique(outDlls.begin(), outDlls.end()), outDlls.end());
    return true;
}

static bool containsDllVB(const std::vector<std::string>& dlls, const std::string& partLower)
{
    for (const auto& d : dlls)
    {
        if (d.find(partLower) != std::string::npos)
            return true;
    }
    return false;
}

json checkPeVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer)
{
    json result;
    json meta;
    json signals = json::array();

    result["type"] = info.magicType;

    if (buffer.size() < 0x40)
    {
        addingVB(signals, "structure_warning", "too_small_for_pe", 7);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    std::uint32_t e_lfanew = 0;
    if (!readU32LEVB(buffer, 0x3C, e_lfanew))
    {
        addingVB(signals, "structure_warning", "no_e_lfanew", 7);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    meta["e_lfanew"] = e_lfanew;

    if (e_lfanew >= buffer.size() || buffer.size() - e_lfanew < 0x18)
    {
        addingVB(signals, "structure_warning", "e_lfanew_oob", 6);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    if (!(buffer[e_lfanew] == 'P' && buffer[e_lfanew + 1] == 'E' && buffer[e_lfanew + 2] == 0 && buffer[e_lfanew + 3] == 0))
    {
        addingVB(signals, "structure_warning", "missing_pe_signature", 6);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    const std::size_t fileHdr = static_cast<std::size_t>(e_lfanew) + 4;

    std::uint16_t numberOfSections = 0;
    std::uint16_t sizeOfOptionalHeader = 0;

    if (!readU16LEVB(buffer, fileHdr + 2, numberOfSections) || !readU16LEVB(buffer, fileHdr + 16, sizeOfOptionalHeader))
    {
        addingVB(signals, "structure_warning", "coff_header_read_fail", 6);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    meta["sections_count"] = static_cast<std::uint32_t>(numberOfSections);
    meta["optional_header_size"] = static_cast<std::uint32_t>(sizeOfOptionalHeader);

    const std::size_t optHdr = fileHdr + 20;

    if (optHdr >= buffer.size() || optHdr + sizeOfOptionalHeader > buffer.size())
    {
        addingVB(signals, "structure_warning", "optional_header_oob", 6);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    std::uint16_t optMagic = 0;
    if (!readU16LEVB(buffer, optHdr + 0, optMagic))
    {
        addingVB(signals, "structure_warning", "optional_header_oob", 6);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    const bool is64 = (optMagic == 0x20B);
    const bool is32 = (optMagic == 0x10B);
    meta["is_64bit"] = is64;

    if (!is32 && !is64)
        addingVB(signals, "structure_warning", "unknown_optional_magic", 6);

    std::uint32_t entryRva = 0;
    if (readU32LEVB(buffer, optHdr + 0x10, entryRva))
        meta["entry_point_rva"] = entryRva;

    const std::size_t ddBase = optHdr + (is64 ? 112 : 96);

    std::uint32_t importRva = 0, importSize = 0;
    std::uint32_t tlsRva = 0, tlsSize = 0;
    std::uint32_t securityOff = 0, securitySize = 0;

    if (ddBase + 8 * 16 <= optHdr + static_cast<std::size_t>(sizeOfOptionalHeader))
    {
        readU32LEVB(buffer, ddBase + 8 * 1 + 0, importRva);
        readU32LEVB(buffer, ddBase + 8 * 1 + 4, importSize);

        readU32LEVB(buffer, ddBase + 8 * 4 + 0, securityOff);
        readU32LEVB(buffer, ddBase + 8 * 4 + 4, securitySize);

        readU32LEVB(buffer, ddBase + 8 * 9 + 0, tlsRva);
        readU32LEVB(buffer, ddBase + 8 * 9 + 4, tlsSize);
    }
    else
    {
        addingVB(signals, "structure_warning", "data_directories_short", 3);
    }

    if (tlsRva != 0)
        addingVB(signals, "execution", "tls_directory_present", 7);

    if (securityOff != 0 && securitySize != 0)
    {
        const std::uint32_t end = securityOff + securitySize;
        if (end <= static_cast<std::uint32_t>(buffer.size()))
            addingVB(signals, "signature", "certificate_table_present", 2);
        else
            addingVB(signals, "structure_warning", "certificate_table_oob", 6);
    }
    else
    {
        addingVB(signals, "signature", "no_certificate_table", 2);
    }

    const std::size_t secHdr = optHdr + static_cast<std::size_t>(sizeOfOptionalHeader);
    const std::size_t secSize = 40;

    if (!inRangeVB(buffer, secHdr, static_cast<std::size_t>(numberOfSections) * secSize))
    {
        addingVB(signals, "structure_warning", "sections_table_oob", 10);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    std::vector<PeSectionVB> secs;
    secs.reserve(numberOfSections);

    std::size_t maxRawEnd = 0;

    int rwxCount = 0;
    int wxCount = 0;
    bool upxFound = false;
    int highEntropyExec = 0;

    bool sectionReadFail = false;

    for (std::uint16_t i = 0; i < numberOfSections; ++i)
    {
        const std::size_t p = secHdr + static_cast<std::size_t>(i) * secSize;

        char name8[8] = {0};
        if (!readBytesVB(buffer, p + 0, name8, 8))
        {
            sectionReadFail = true;
            break;
        }

        std::string sname(name8, name8 + 8);
        while (!sname.empty() && (sname.back() == '\0' || sname.back() == ' '))
            sname.pop_back();

        PeSectionVB s;
        s.name = sname;

        if (!readU32LEVB(buffer, p +  8, s.vsize) ||
            !readU32LEVB(buffer, p + 12, s.vaddr) ||
            !readU32LEVB(buffer, p + 16, s.rawSize) ||
            !readU32LEVB(buffer, p + 20, s.rawPtr) ||
            !readU32LEVB(buffer, p + 36, s.characteristics))
        {
            sectionReadFail = true;
            break;
        }

        secs.push_back(s);

        if (s.rawPtr != 0 && s.rawSize != 0)
        {
            const std::size_t end = static_cast<std::size_t>(s.rawPtr) + static_cast<std::size_t>(s.rawSize);
            maxRawEnd = std::max(maxRawEnd, end);
        }

        if (isRWXVB(s.characteristics))
            rwxCount++;
        else if (isWXVB(s.characteristics))
            wxCount++;

        std::string nm = s.name;
        toLowerVB(nm);
        if (nm == "upx0" || nm == "upx1" || nm == "upx2" || nm.find("upx") != std::string::npos)
            upxFound = true;

        if (hasExecVB(s.characteristics) && s.rawPtr != 0 && s.rawSize != 0 && static_cast<std::size_t>(s.rawPtr) < buffer.size())
        {
            const double h = calcEntropyRangeVB(buffer, static_cast<std::size_t>(s.rawPtr), static_cast<std::size_t>(s.rawSize));
            if (h >= 7.2)
                highEntropyExec++;
        }
    }

    if (sectionReadFail)
    {
        addingVB(signals, "structure_warning", "section_header_read_fail", 10);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    meta["rwx_sections"] = rwxCount;
    meta["wx_sections"] = wxCount;
    meta["high_entropy_exec_sections"] = highEntropyExec;

    if (rwxCount > 0)
        addingVB(signals, "memory", "rwx_section_present", 10);
    else if (wxCount > 0)
        addingVB(signals, "memory", "wx_section_present", 9);

    if (upxFound)
        addingVB(signals, "packer", "upx_section_name", 8);

    if (highEntropyExec > 0)
        addingVB(signals, "packer", "high_entropy_exec_section", 7);

    if (entryRva != 0)
    {
        for (const auto& s : secs)
        {
            const std::uint32_t start = s.vaddr;
            const std::uint32_t end   = start + std::max(s.vsize, s.rawSize);

            if (entryRva >= start && entryRva < end)
            {
                std::string nm = s.name;
                toLowerVB(nm);
                meta["entry_point_section"] = nm;
                break;
            }
        }
    }

    if (maxRawEnd > 0 && maxRawEnd < buffer.size())
    {
        const std::size_t overlay = buffer.size() - maxRawEnd;
        meta["overlay_size"] = overlay;

        if (overlay >= 1024 * 1024)
            addingVB(signals, "overlay", "overlay>=1mb", 7);
        else if (overlay >= 200 * 1024)
            addingVB(signals, "overlay", "overlay>=200kb", 4);
        else if (overlay >= 20 * 1024)
            addingVB(signals, "overlay", "overlay>=20kb", 2);
    }
    else
    {
        meta["overlay_size"] = 0;
    }

    std::vector<std::string> dlls;
    if (!parseImportsVB(buffer, secs, importRva, importSize, dlls))
        addingVB(signals, "structure_warning", "imports_parse_failed", 4);

    meta["imports_dll_count"] = static_cast<std::uint32_t>(dlls.size());

    if (containsDllVB(dlls, "wininet") || containsDllVB(dlls, "winhttp") || containsDllVB(dlls, "urlmon"))
        addingVB(signals, "network", "import_wininet_winhttp_urlmon", 6);

    if (containsDllVB(dlls, "ws2_32") || containsDllVB(dlls, "dnsapi"))
        addingVB(signals, "network", "import_winsock_dnsapi", 5);

    if (containsDllVB(dlls, "crypt32") || containsDllVB(dlls, "bcrypt") || containsDllVB(dlls, "advapi32"))
        addingVB(signals, "crypto", "import_crypto_advapi", 3);

    if (dlls.size() <= 2 && (highEntropyExec > 0 || upxFound || rwxCount > 0 || wxCount > 0))
        addingVB(signals, "packer", "few_imports_with_packing_hints", 5);

    if (numberOfSections >= 20)
        addingVB(signals, "structure_warning", "many_sections>=20", 2);

    result["meta"] = meta;
    result["signals"] = signals;
    return result;
}