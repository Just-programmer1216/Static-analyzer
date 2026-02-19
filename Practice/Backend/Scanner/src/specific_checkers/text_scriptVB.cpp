#include "../../include/specific_checkers/text_scriptVB.hpp"

#include "../../include/utils/to_lowerVB.hpp"
#include "../../include/utils/addingVB.hpp"

#include <cctype>
#include <string>

static std::string bufferToTextVB(const std::vector<unsigned char>& buffer, bool& isUTF16BE)
{
    isUTF16BE = false;

    if (buffer.size() >= 2 && buffer[0] == 0xFE && buffer[1] == 0xFF)
    {
        isUTF16BE = true;
        return {};
    }

    std::string out;
    
    if (buffer.size() >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE)
    {

        out.reserve(buffer.size() / 2);

        for (std::size_t i = 2; i + 1 < buffer.size(); i += 2)
        {
            unsigned char l = buffer[i];
            unsigned char h = buffer[i + 1];

            if (h == 0x00 && (l == '\n' || l == '\r' || l == '\t' || (l >= 0x20 && l <= 0x7E)))
                out.push_back(static_cast<char>(l));
            else
                out.push_back(' ');
        }
        return out;
    }

    out.reserve(buffer.size());

    for (unsigned char c : buffer)
    {
        if (c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c <= 0x7E))
            out.push_back(static_cast<char>(c));
        else
            out.push_back(' ');
    }

    return out;
}

static int countBlocksVB(const std::string& text)
{
    int count = 0;
    int current = 0;
    bool inBlock = false;

    for (unsigned char c : text)
    {
        if (c=='\n' || c=='\r' || c==' ' || c=='\t')
            continue;
        if (std::isalnum(c) || c == '+' || c == '/' || c == '=')
        {
            current++;
            if (!inBlock && current > 40)
            {
                count++;
                inBlock = true;
            }
        }
        else
        {
            current = 0;
            inBlock = false;
        }
    }

    return count;
}

struct ScriptPatternVB
{
    std::string category;
    std::string pattern;
    int severity;
};

static std::vector<ScriptPatternVB> getPatternsVB(const std::string& type)
{
    if (type == "ps1")
    {
        return {
            { "download",     "invoke-webrequest",               4 },
            { "download",     "iwr ",                            2 },
            { "exec",         "iex",                             8 },
            { "exec",         "invoke-expression",               8 },
            { "exec",         "start-process",                   3 },
            { "network",      "new-object system.net.webclient", 6 },
            { "network",      "system.net.webclient" ,           5 },
            { "download",     "system.net.webrequest" ,          5 },
            { "download",     "downloadfile(" ,                  6 },
            { "download",     "downloadstring(" ,                6 },
            { "persistence",  "register-scheduledtask" ,         8 },
            { "persistence",  "register-scheduledjob" ,          7 },
            { "persistence",  "new-scheduledtask" ,              7 },
            { "destructive",  "format-volume" ,                  10 },
            { "obfuscation",  "-encodedcommand" ,                10 },
            { "obfuscation",  "-executionpolicy bypass" ,        6 },
            { "obfuscation",  "-ep bypass" ,                     6 },
            { "obfuscation",  "frombase64string" ,               6 },
            { "evasion",      "-windowstyle hidden" ,            6 },
            { "evasion",      "-w hidden " ,                     5 },
            { "evasion",      "add-mppreference" ,               8 },
            { "evasion",      "set-mppreference" ,               8 },
            { "lolbas",       "bitsadmin" ,                      7 }
        };
    }

    if (type == "bat" || type == "cmd")
    {
        return {
            { "exec",        "powershell",       3 },
            { "exec",        "-enc ",            10 },
            { "exec",        "cmd /c",           2 },
            { "obfuscation", "-encodedcommand ", 10 },
            { "network",     "ftp ",             3 },
            { "download",    "curl ",            3 },
            { "download",    "wget ",            3 },
            { "persistence", "schtasks",         7 },
            { "destructive", "del /s",           6 },
            { "destructive", "format c:",        10 },
            { "destructive", "format /q",        8 },
            { "lolbas",      "bitsadmin",        7 },
            { "lolbas",      "certutil",         7 }
        };
    }

    if (type == "js")
    {
        return {
            { "exec",        "eval(",          6 },
            { "download",    "xmlhttp",        4 },
            { "download",    "adodb.stream",   9 },
            { "network",     "msxml2.xmlhttp", 6 },
            { "obfuscation", "atob(",          5 },
            { "lolbas",      "wscript.shell",  9 }
        };
    }

    if (type == "vbs")
    {
        return {
            { "exec",        "execute",        6 },
            { "download",    "xmlhttp",        4 },
            { "download",    "adodb.stream",   9 },
            { "network",     "msxml2.xmlhttp", 6 },
            { "obfuscation", "base64decode",   5 },
            { "lolbas",      "wscript.shell",  9 }
        };
    }

    if (type == "py")
    {
        return {
            { "exec",        "os.system",     6 },
            { "exec",        "subprocess",    4 },
            { "exec",        "popen",         5 },
            { "exec",        "eval(",         6 },
            { "exec",        "exec(",         6 },
            { "download",    "requests.get",  2 },
            { "download",    "requests.post", 2 },
            { "download",    "urllib",        2 },
            { "destructive", "shutil.rmtree", 6 },
            { "destructive", "rm -rf /",      10 },
            { "destructive", "rm -rf ",       8 },
            { "obfuscation", "marshal",       6 },
            { "obfuscation", "compile(",      4 }
        };
    }
    return {};
}

static std::vector<ScriptPatternVB> getUniversalPatternsVB()
{
    return {
        { "obfuscation", "-encodedcommand",   10 },
        { "obfuscation", "frombase64string",  6 },
        { "download",    "adodb.stream",      9 },
        { "destructive", "format c:",         10 },
        { "destructive", "rm -rf /",          10 },
        { "destructive", "rm -rf ",           8 },
        { "exec",        "-enc ",             10 },
        { "exec",        "invoke-expression", 8 },
        { "exec",        "iex",               8 },
        { "lolbas",      "wscript.shell",     9 }
    };
}

static bool isKnownTypeVB(const std::string& type)
{
    return type == "ps1" || type == "bat" || type == "cmd" || type == "js"  || type == "vbs" || type == "py";
}

static std::string detectTypeVB(const std::string& text)
{
    if (text.find("powershell") != std::string::npos ||
        text.find("invoke-webrequest") != std::string::npos ||
        text.find("frombase64string") != std::string::npos ||
        text.find("-encodedcommand") != std::string::npos)
        return "ps1";

    if (text.find("@echo off") != std::string::npos ||
        text.find("setlocal") != std::string::npos ||
        text.find("cmd /c") != std::string::npos)
        return "bat";

    if (text.find("wscript.shell") != std::string::npos ||
        text.find("createobject") != std::string::npos ||
        text.find("executeglobal") != std::string::npos)
        return "vbs";

    if (text.find("activexobject") != std::string::npos ||
        text.find("document.write") != std::string::npos ||
        text.find("atob(") != std::string::npos)
        return "js";

    if (text.find("import ") != std::string::npos &&
        (text.find("subprocess") != std::string::npos ||
         text.find("os.system") != std::string::npos))
        return "py";

    return "unknown";
}

json checkScriptVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer, bool& scriptHint)
{
    json result;
    json meta;
    json signals = json::array();
    bool isUTF16BE = false;
    std::string text = bufferToTextVB(buffer, isUTF16BE);
    std::string scriptExt = info.extension;
    if (isUTF16BE)
    {
        result["type"] = "unknown";
        meta["support"] = "partial";
         addingVB(signals, "structure_warning", "utf16_be_not_supported", 4);
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }
    
    std::string detectedExt = "unknown";
    bool knownType = isKnownTypeVB(scriptExt);

    toLowerVB(text);

    if (!knownType && scriptHint)
    {
        detectedExt = detectTypeVB(text);
        if (detectedExt != "unknown")
            scriptExt = detectedExt;
    }
    knownType = isKnownTypeVB(scriptExt);
    
    if(knownType)
    {
        result["type"] = scriptExt;
        meta["detected_extension"] = scriptExt;
    }
    else
    {
        result["type"] = detectedExt;
        meta["detected_extension"] = detectedExt;
    }

    int blocks = countBlocksVB(text);
    meta["base64_blocks"] = blocks;
    if(blocks >=3)
        addingVB(signals, "obfuscation", "high_base64_blocks_detected", 6);
    else if(blocks >0)
        addingVB(signals, "obfuscation", "base64_blocks_detected", 4);
    
    meta["declared_extension"] = info.extension;
    meta["extension_recognized"] = knownType;

    if (detectedExt != "unknown")
        addingVB(signals, "extension_mismatch", detectedExt + " != " + info.extension, 10);
    if(!knownType && detectedExt == "unknown")
    {
       std::vector<ScriptPatternVB> patterns = getUniversalPatternsVB();
        for (const auto& p : patterns)
        {
            if (text.find(p.pattern) != std::string::npos)
              addingVB(signals, p.category, p.pattern, p.severity);
        }
        result["meta"] = meta;
        result["signals"] = signals;
        return result;
    }

    std::vector<ScriptPatternVB> patterns = getPatternsVB(scriptExt);

    for (const auto& p : patterns)
    {
        if (text.find(p.pattern) != std::string::npos)
            addingVB(signals, p.category, p.pattern, p.severity);
    }

    result["meta"] = meta;
    result["signals"] = signals;

    return result;
}