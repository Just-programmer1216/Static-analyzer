#include "../include/file_infoVB.hpp"
#include "../include/utils/buffer_searchVB.hpp"

#include <fstream>
#include <algorithm>
#include <cctype>

bool readFileVB(const std::string& path, std::vector<unsigned char>& buffer)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    buffer.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    return true;
}

std::string extractFilenameVB(const std::string& path)
{
    std::size_t pos = path.find_last_of("/\\");
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}

std::string extractExtVB(const std::string& filename)
{
    std::size_t pos = filename.find_last_of('.');
    if (pos == std::string::npos) return "";
    std::string ext = filename.substr(pos + 1);
    while (!ext.empty() && isspace(ext.back()))
        ext.pop_back();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext;
}

bool isProbablyTextVB(const std::vector<unsigned char>& buffer)
{
    if (buffer.empty()) return false;
    //UTF-16 
    if (buffer.size() >= 2) 
    {
        if ((buffer[0] == 0xFF && buffer[1] == 0xFE) || (buffer[0] == 0xFE && buffer[1] == 0xFF))
            return true;
    }
    // UTF-8 
    for (unsigned char c : buffer)
    {
        if (c == 0) return false;
        if (c < 8 && c != '\n' && c != '\r' && c != '\t')
        return false;
    }

    return true;
}

std::string fileTypeVB(const std::string& magic, const std::string& ext, const std::vector<unsigned char>& buffer)
{
    if (buffer.empty())return "empty";

    if (magic == "ole")
    {
    //Temporary comment due to disablind missmatch
       //if (ext == "doc" || ext == "xls" || ext == "ppt")
            return "office";
    //return "binary";
    }
    if (magic == "pdf")return "pdf";
    if (magic == "pe")return "pe";
    if (magic == "png" || magic == "jpg" ||
        magic == "gif" || magic == "bmp") return "image";

    if (magic == "zip") 
    {
        if ((ext == "docx" || ext == "xlsx" || ext == "pptx"))
            return "office";
        if(bufferSearchVB(buffer, "[Content_Types].xml"))
            return "office";
        return "zip";
    }

    if (ext == "bat" || ext == "cmd" || ext == "ps1" ||
        ext == "js"  || ext == "vbs" || ext == "py")
        return "script";

    if (isProbablyTextVB(buffer))
        return "text";

    return "binary";
}

FileInfoVB getFileInfoVB(const std::string& path, const std::vector<unsigned char>& buffer)
{
    FileInfoVB info;

    info.filename = extractFilenameVB(path);
    info.extension = extractExtVB(info.filename);
    info.size = buffer.size();

    info.magicType = magicTypeVB(buffer);
    info.logicalType = fileTypeVB(info.magicType, info.extension, buffer);

    return info;
}