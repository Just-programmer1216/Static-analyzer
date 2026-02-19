#include "../../include/default_checkers/mismatchVB.hpp"

#include <string>

static bool isAllowedVB(const std::string& ext, const std::string& magicType, const std::string& logicalType)
{
    if ((ext == "docx" || ext == "xlsx" || ext == "pptx") &&
        magicType == "zip" &&
        logicalType == "office")
    {
        return true;
    }

    if ((ext == "doc" || ext == "xls" || ext == "ppt") &&
        magicType == "ole" &&
        logicalType == "office")
    {
        return true;
    }

    if (logicalType == "image" &&
       (magicType == "png" || magicType == "jpg" || 
        magicType == "gif" || magicType == "bmp"))
    {
        if (ext == "png" || ext == "jpg" || ext == "jpeg" ||
            ext == "gif" || ext == "bmp")
            return true;
    }

    if (ext == "pdf" && magicType == "pdf")
        return true;

    if (ext == "pdf" && magicType == "pdf")
        return true;

    if ((ext == "exe" || ext == "dll" || ext == "scr" || ext == "sys" || ext == "ocx" || ext == "cpl") && magicType == "pe")
        return true;

    if (ext == "zip" && magicType == "zip" && logicalType == "zip")
        return true;
 
    return false;
}


json checkExtMismatchVB(const FileInfoVB& info)
{
    json result;
    result["found"] = false;
    result["extension"] = info.extension;
    result["magic"] = info.magicType;
    result["logical"] = info.logicalType;

    if (info.extension.empty())
        return result;

    if (info.magicType == "unknown")
        return result;

    if (isAllowedVB(info.extension, info.magicType, info.logicalType))
        return result;
  
    result["found"] = true;
    return result;
}
