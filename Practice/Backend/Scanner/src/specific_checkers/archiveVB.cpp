#include "../../include/specific_checkers/archiveVB.hpp"

#include "../../include/utils/addingVB.hpp"
#include "../../include/utils/cdparserVB.hpp"

#include <algorithm>
#include <cstdint>
#include <string>

static bool traversalVB(const std::string& name)
{
    if (name.find("../") != std::string::npos || name.find("..\\") != std::string::npos)
        return true;

    if (!name.empty() && (name[0] == '/' || name[0] == '\\'))
        return true;

    if (name.size() >= 3 && name[1] == ':' &&
        (name[2] == '\\' || name[2] == '/'))
        return true;

    return false;
}

static bool endVB(const std::string& s, const std::string& suffix)
{
    if (s.size() < suffix.size())
        return false;

    return std::equal(suffix.rbegin(), suffix.rend(), s.rbegin());
}

static bool doubleExtVB(const std::string& name)
{
    static const std::vector<std::string> bad = 
    {
        ".exe", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".py" ,".dll", ".scr", ".sys", ".msi", ".lnk", ".com", ".ocx", ".cpl"
    };

    for (const auto& ext : bad)
    {
        if (endVB(name, ext))
        {
            const std::size_t firstDot = name.find('.');
            const std::size_t lastDot  = name.rfind('.');
            if (firstDot != std::string::npos && lastDot != std::string::npos && firstDot != lastDot)
                return true;
        }
    }

    return false;
}

struct ZipPatternVB
{
    std::string category;
    std::string pattern;
    int severity;
};

static std::vector<ZipPatternVB> getPatternsVB()
{
    return {
        { "executables",      ".exe",        4 },
        { "executables",      ".scr",        4 },
        { "executables",      ".com",        4 },
        { "executables",      ".msi",        4 },
        { "executables",      ".dll",        3 },
        { "scripts",          ".bat",        3 },
        { "scripts",          ".cmd",        3 },
        { "scripts",          ".ps1",        3 },
        { "scripts",          ".vbs",        3 },
        { "scripts",          ".js",         3 },
        { "suspicious_names", "autorun.inf", 5 },
        { "suspicious_names", ".lnk",        5 }
    };
}

json checkArchiveVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer)
{
    json result;
    json meta;
    json signals = json::array();

    result["type"] = info.magicType;

    std::vector<ZipNameVB> names;
    std::uint16_t declaredTotalEntries = 0;
    bool zip64Possible = false;
    bool structureValid = true;

    const bool zipParsed = parseCDVB(buffer, names, declaredTotalEntries, zip64Possible);

    meta["zip_structure_parsed"] = zipParsed;
    meta["zip64_possible"] = zip64Possible;
    meta["entries_count"] = static_cast<int>(names.size());

    if (zip64Possible)
    {
        addingVB(signals, "structure_warning", "zip64_not_supported", 4);
        meta["support"] = "partial";

        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    const std::size_t MAX_ENTRIES = 5000;

    if (declaredTotalEntries > MAX_ENTRIES || names.size() >= MAX_ENTRIES)
        addingVB(signals, "structure_warning", "entries_truncated", 3);

    if (!zipParsed)
    {
        meta["structure_valid"] = !structureValid;

        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    bool travers = false;

    std::size_t exeCount = 0;
    std::size_t dllCount = 0;
    std::size_t scriptCount = 0;
    std::size_t autorunOrLnkCount = 0;
    std::size_t doubleExtCount = 0;
    std::size_t maxNameLen = 0;

    const std::vector<ZipPatternVB> patterns = getPatternsVB();

    for (const auto& n : names)
    {
        maxNameLen = std::max(maxNameLen, n.name.size());

        if (!travers && traversalVB(n.name))
            travers = true;

        const std::string filename = extractFilenameVB(n.name);

        for (const auto& p : patterns)
        {
            if (!endVB(filename, p.pattern))
                continue;

            if (p.category == "executables")
            {
                if (p.pattern == ".dll")
                    dllCount++;
                else
                    exeCount++;
            }
            else if (p.category == "scripts")
            {
                scriptCount++;
            }
            else if (p.category == "suspicious_names")
                autorunOrLnkCount++;
            break;
        }

        if (doubleExtVB(filename))
            doubleExtCount++;
    }
    meta["structure_valid"] = structureValid;
    meta["max_name_len"] = maxNameLen;
    meta["has_path_traversal"] = travers;

    meta["exe_count"] = exeCount;
    meta["dll_count"] = dllCount;
    meta["script_count"] = scriptCount;
    meta["autorun_or_lnk_count"] = autorunOrLnkCount;
    meta["inner_double_ext_count"] = doubleExtCount;

    if(maxNameLen > 200)
        addingVB(signals, "high_name_length", "long_filename_in_archive", 3);

    if (travers)
        addingVB(signals, "path_traversal", "zip_path_traversal", 10);// Changed severity to 10 because of the potential impact of path traversal vulnerabilities

    if (exeCount > 0)
        addingVB(signals, "executables", "executables_in_archive", 4);

    if (dllCount > 0)
        addingVB(signals, "executables", "dll_in_archive", 3);

    if (scriptCount > 0)
        addingVB(signals, "scripts", "scripts_in_archive", 3);

    if (autorunOrLnkCount > 0)
        addingVB(signals, "suspicious_names", "autorun_or_lnk", 5);

    if (doubleExtCount > 0)
        addingVB(signals, "suspicious_names", "double_extension_in_archive", 6);


    result["meta"] = meta;
    result["signals"] = signals;
    return result;
}