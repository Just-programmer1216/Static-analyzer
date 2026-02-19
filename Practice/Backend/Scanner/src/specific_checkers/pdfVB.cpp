#include "../../include/specific_checkers/pdfVB.hpp"

#include "../../include/utils/buffer_searchVB.hpp"
#include "../../include/utils/to_lowerVB.hpp"
#include "../../include/utils/addingVB.hpp"

#include <string>

static bool isWsVB(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == 0;
}

static int countTokenVB(const std::vector<unsigned char>& buffer, const std::string& token)
{
    if (token.empty() || buffer.size() < token.size())
        return 0;

    int count = 0;

    for (std::size_t i = 0; i + token.size() <= buffer.size(); ++i)
    {
        if (i > 0 && !isWsVB(buffer[i - 1]))
            continue;

        bool ok = true;

        for (std::size_t j = 0; j < token.size(); ++j)
        {
            if (toLowerByteVB(buffer[i + j]) != toLowerByteVB(static_cast<unsigned char>(token[j])))
            {
                ok = false;
                break;
            }
        }

        if (!ok)
            continue;

        std::size_t r = i + token.size();
        if (r < buffer.size() && !isWsVB(buffer[r]))
            continue;

        ++count;
        i += token.size() - 1;
    }

    return count;
}

static bool isDelimVB(unsigned char c)
{
    if(isWsVB(c))
        return true;
         
    switch (c)
    {
        case '(':
        case ')':
        case '<':
        case '>':
        case '[':
        case ']':
        case '{':
        case '}':
        case '/':
        case '%':
            return true;
        default:
            return false;
    }
}

static bool bufferShortSearchVB(const std::vector<unsigned char>& buffer, const std::string& shortPattern)
{
    if (shortPattern.empty() || buffer.size() < shortPattern.size())
        return false;

    for (std::size_t i = 0; i + shortPattern.size() <= buffer.size(); ++i)
    {
        bool ok = true;

        for (std::size_t j = 0; j < shortPattern.size(); ++j)
        {
            if (toLowerByteVB(buffer[i + j]) != toLowerByteVB(static_cast<unsigned char>(shortPattern[j])))
            {
                ok = false;
                break;
            }
        }

        if (!ok)
            continue;

        const std::size_t end = i + shortPattern.size();

        if (end >= buffer.size())
            return true;

        if (isDelimVB(buffer[end]))
            return true;
    }

    return false;
}

struct PdfPatternVB
{
    std::string category;
    std::string pattern;
    int severity;
};

static std::vector<PdfPatternVB> getPatternsVB()
{
    return {
        { "javascript",         "/javascript",   10 },
        { "javascript",         "/js",           6 },
        { "open_action",        "/openaction",   8 },
        { "additional_actions", "/aa",           6 },
        { "launch_action",      "/launch",       7 },
        { "embedded_file",      "/embeddedfile", 8 },
        { "filespec",           "/filespec",     6 },
        { "uri_action",         "/uri",          4 },
        { "richmedia",          "/richmedia",    6 },
        { "xfa",                "/xfa",          5 },
    };
}

json checkPdfVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer)
{
    json result;
    json meta;
    json signals = json::array();

    result["type"] = info.magicType;

    int streams = countTokenVB(buffer, "stream");
    int endstreams = countTokenVB(buffer, "endstream");

    meta["streams"] = streams;
    meta["endstreams"] = endstreams;

    meta["linearized"] = bufferSearchVB(buffer, "/linearized");

    std::vector<PdfPatternVB> patterns = getPatternsVB();
    bool pres = false;
    for (const auto& p : patterns)
    {
        if (p.pattern == "/js" || p.pattern == "/aa" || p.pattern == "/uri")
            pres = bufferShortSearchVB(buffer, p.pattern);
        else
            pres = bufferSearchVB(buffer, p.pattern);
        if (pres)
            addingVB(signals, p.category, p.pattern, p.severity);
    }

    if (streams != endstreams)
        addingVB(signals, "structure_warning", "stream_mismatch", 3);

    if (streams >= 1500)
        addingVB(signals, "structure_warning", "many_streams>=1500", 6);
    else if (streams >= 800)
        addingVB(signals, "structure_warning", "many_streams>=800", 4);
    else if (streams >= 300)
        addingVB(signals, "structure_warning", "many_streams>=300", 2);

    result["meta"] = meta;
    result["signals"] = signals;

    return result;
}