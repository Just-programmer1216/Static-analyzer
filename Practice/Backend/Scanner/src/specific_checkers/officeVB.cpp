#include "../../include/specific_checkers/officeVB.hpp"

#include "../../include/utils/buffer_searchVB.hpp"
#include "../../include/utils/addingVB.hpp"
#include "../../include/utils/cdparserVB.hpp"

#include <cstdint>
#include <string>

static bool equalsVB(const std::vector<ZipNameVB>& entries, const std::string& exact)
{
    for (const auto& e : entries)
    {
        if (e.name == exact)
            return true;
    }

    return false;
}

static bool startVB(const std::vector<ZipNameVB>& entries, const std::string& prefix)
{
    for (const auto& e : entries)
    {
        if (e.name.rfind(prefix, 0) == 0)
            return true;
    }

    return false;
}

static bool containsVB(const std::vector<ZipNameVB>& entries, const std::string& part)
{
    for (const auto& e : entries)
    {
        if (e.name.find(part) != std::string::npos)
            return true;
    }

    return false;
}

static bool isOoxmlVB(const std::vector<ZipNameVB>& names)
{
    const bool hasContentTypes = equalsVB(names, "[content_types].xml");
    const bool hasRootRels = equalsVB(names, "_rels/.rels");

    const bool hasMain =
        startVB(names, "word/") ||
        startVB(names, "xl/") ||
        startVB(names, "ppt/");

    return hasContentTypes && hasRootRels && hasMain;
}

struct OoxmlPatternVB
{
    std::string category;
    std::string patternLower;
    int severity;
    enum class Match
    {
        Equals,
        StartsWith,
        Contains
    } match;
};

static std::vector<OoxmlPatternVB> getOoxmlPatternsVB()
{
    return {
        { "has_macros",       "vbaproject.bin",       10, OoxmlPatternVB::Match::Contains },
        { "external_links",   "xl/externallinks/",     6, OoxmlPatternVB::Match::StartsWith },
        { "embedded_objects", "/embeddings/",          7, OoxmlPatternVB::Match::Contains },
        { "embedded_objects", "oleobject",             7, OoxmlPatternVB::Match::Contains },
        { "activex",          "word/activex/",         6, OoxmlPatternVB::Match::StartsWith },
        { "activex",          "xl/activex/",           6, OoxmlPatternVB::Match::StartsWith },
        { "activex",          "ppt/activex/",          6, OoxmlPatternVB::Match::StartsWith }
    };
}

static bool matchOoxmlVB(const std::vector<ZipNameVB>& names, const OoxmlPatternVB& p)
{
    if (p.match == OoxmlPatternVB::Match::Equals)
        return equalsVB(names, p.patternLower);

    if (p.match == OoxmlPatternVB::Match::StartsWith)
        return startVB(names, p.patternLower);

    return containsVB(names, p.patternLower);
}

struct OlePatternVB
{
    std::string category;
    std::string pattern;
    int severity;
};

static std::vector<OlePatternVB> getOlePatternsVB()
{
    return {
        { "encrypted",        "EncryptedPackage", 7 },
        { "encrypted",        "EncryptionInfo",   6 },
        { "has_macros",       "VBA/",             10 },
        { "has_macros",       "PROJECT",          8 },
        { "has_macros",       "PROJECTWM",        4 },
        { "has_macros",       "ThisDocument",     6 },
        { "embedded_objects", "ObjectPool",       7 },
        { "embedded_objects", "Ole10Native",      7 }
    };
}

json checkOfficeVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer)
{
    json result;
    json meta;
    json signals = json::array();

    result["type"] = info.magicType;

    if (info.magicType == "ole")
    {
        std::vector<OlePatternVB> patterns = getOlePatternsVB();

        for (const auto& p : patterns)
        {
            if (bufferSearchVB(buffer, p.pattern))
                addingVB(signals, p.category, p.pattern, p.severity);
        }

        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    result["type"] = "ooxml";

    std::vector<ZipNameVB> names;
    std::uint16_t declaredTotalEntries = 0;
    bool zip64Possible = false;

    const bool zipParsed = parseCDVB(buffer, names, declaredTotalEntries, zip64Possible);

    meta["zip_structure_parsed"] = zipParsed;
    meta["zip64_possible"] = zip64Possible;
    if (zip64Possible)
    {
        addingVB(signals, "structure_warning", "zip64_not_supported", 4);
        meta["support"] = "partial";
    }

    meta["entries_count"] = static_cast<int>(names.size());

    const std::size_t MAX_ENTRIES = 5000;

    if (declaredTotalEntries > MAX_ENTRIES || names.size() >= MAX_ENTRIES)
        addingVB(signals, "structure_warning", "entries_truncated", 3);

    if (!zipParsed)
    {
        meta["structure_valid"] = bufferSearchVB(buffer, "[Content_Types].xml");

        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    const bool structureValid = isOoxmlVB(names);
    meta["structure_valid"] = structureValid;

    if (!structureValid)
        addingVB(signals, "structure_warning", "invalid_ooxml_structure", 5);

    std::vector<OoxmlPatternVB> ooxmlPatterns = getOoxmlPatternsVB();

    for (const auto& p : ooxmlPatterns)
    {
        if (matchOoxmlVB(names, p))
            addingVB(signals, p.category, p.patternLower, p.severity);
    }

    result["meta"] = meta;
    result["signals"] = signals;

    return result;
}