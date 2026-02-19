#include "../../include/default_checkers/double_extVB.hpp"

#include <string>
#include <vector>
#include <algorithm>

static bool isDangerousExtVB(const std::string& ext)
{
    static const std::vector<std::string> bad =
    {
        "exe", "js", "vbs", "ps1", "bat", "cmd", "py" ,"dll", "scr", "sys", "msi", "lnk", "com", "ocx", "cpl"
    };
    return std::find(bad.begin(), bad.end(), ext) != bad.end();
}

json checkDoubleExtVB(const FileInfoVB& info)
{
    json result;
    result["found"] = false;
    result["extensions"] = json::array();

    const std::string& name = info.filename;
    std::size_t pos = 0;
    std::vector<std::size_t> dotPos;

    while ((pos = name.find('.', pos)) != std::string::npos)
    {
        dotPos.push_back(pos);
        pos++;
    }

    if (dotPos.size() < 2) 
        return result;

    std::vector<std::string> exts;

    for (std::size_t i = 0; i < dotPos.size(); ++i)
    {
        std::size_t start = dotPos[i] + 1;
        std::size_t end = (i + 1 < dotPos.size()) ? dotPos[i+1] : name.size();
        std::string ext = name.substr(start, end - start);

        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);

        if (!ext.empty())
            exts.push_back(ext);
    }

    result["extensions"] = exts;

    if (isDangerousExtVB(exts.back()))
    {
        if (exts.size() >= 2 && exts[exts.size() - 2] != exts.back())
            result["found"] = true;
    }

    return result;
}
