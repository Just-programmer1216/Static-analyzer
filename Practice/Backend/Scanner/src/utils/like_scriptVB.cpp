#include "../../include/utils/like_scriptVB.hpp"
#include "../../include/utils/buffer_searchVB.hpp"

#include <string>

bool likeScriptVB(const std::vector<unsigned char>& buffer)
{
    if (buffer.empty())
        return false;

    const std::size_t LIMIT = 64 * 1024;
    const std::size_t n = (buffer.size() < LIMIT) ? buffer.size() : LIMIT;

     const std::vector<unsigned char> head(buffer.begin(), buffer.begin() + n);

    static const std::vector<std::string> markers =
    {
        "powershell",
        "invoke-webrequest",
        "invoke-expression",
        "frombase64string",
        "-enc",
        "wscript",
        "cscript",
        "cmd.exe",
        "mshta",
        "rundll32",
        "regsvr32",
        "curl ",
        "wget ",
        "eval(",
        "atob(",
        "document.write"
    };

    for (const auto& m : markers)
    {
        if(bufferSearchVB(head,m))
            return true;
    }

    return false;
}