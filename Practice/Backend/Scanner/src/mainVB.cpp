#include <iostream>
#include <vector>
#include <string>

#include "../include/json.hpp"
#include "../include/file_infoVB.hpp"
#include "../include/scoreVB.hpp"

#include "../include/default_checkers/entropyVB.hpp"
#include "../include/default_checkers/double_extVB.hpp"
#include "../include/default_checkers/mismatchVB.hpp"

#include "../include/specific_checkers/pdfVB.hpp"
#include "../include/specific_checkers/officeVB.hpp"
#include "../include/specific_checkers/peVB.hpp"
#include "../include/specific_checkers/archiveVB.hpp"
#include "../include/specific_checkers/imageVB.hpp"
#include "../include/specific_checkers/text_scriptVB.hpp"

#include "../include/utils/like_scriptVB.hpp"

using json = nlohmann::json;



int main(int argc, char* argv[])
{
    json result;

    if (argc < 2)
    {
        result["error"] = "No file path provided";
        std::cout << result.dump(4);
        return 1;
    }

    const std::string filePath = argv[1];

    std::vector<unsigned char> buffer;
    if (!readFileVB(filePath, buffer))
    {
        result["error"] = "Failed to read file";
        std::cout << result.dump(4);
        return 1;
    }
    
    const FileInfoVB info = getFileInfoVB(filePath, buffer);

    json defaultChecks;

    defaultChecks["entropy"] = checkEntropyVB(info, buffer);
    defaultChecks["double_extension"] = checkDoubleExtVB(info);
    defaultChecks["extension_mismatch"] = checkExtMismatchVB(info);

    std::string dispatchType = info.logicalType;
    bool scriptHint = false;

    if (dispatchType == "text")
    {
        if (likeScriptVB(buffer))
        {
            scriptHint = true;
            dispatchType = "script";
        }
    }

    json specificCheck = json::object();
    bool hasSpecific = false;

    if (dispatchType == "pdf")
    {
        specificCheck = checkPdfVB(info, buffer);
        hasSpecific = true;
    }
    else if (dispatchType == "office")
    {
        specificCheck = checkOfficeVB(info, buffer);
        hasSpecific = true;
    }
    else if (dispatchType == "pe")
    {
        specificCheck = checkPeVB(info, buffer);
        hasSpecific = true;
    }
    else if (dispatchType == "zip")
    {
        specificCheck = checkArchiveVB(info, buffer);
        hasSpecific = true;
    }
    else if (dispatchType == "image")
    {
        specificCheck = checkImageVB(info, buffer);
        hasSpecific = true;
    }
    else if (dispatchType == "script")
    {
        specificCheck = checkScriptVB(info, buffer, scriptHint);
        hasSpecific = true;

        if (scriptHint)
        {       
            specificCheck["meta"]["original_logical_type"] = info.logicalType;
            specificCheck["meta"]["original_extension"] = info.extension;
        }
    }
    
    json details;
    details["default_checks"] = defaultChecks;
    details["dispatch_type"] = dispatchType;

    result["filename"] = info.filename;
    result["extension"] = info.extension;
    result["magicType"] = info.magicType;
    result["logicalType"] = info.logicalType;
    result["size"] = info.size;
    if (hasSpecific)
    {
        details["specific_check"] = specificCheck;
        ScoreVB score = computeScoreVB(defaultChecks, specificCheck);
        result["supported"] = true;
        result["score"] = score.total;
        result["threat_level"] = score.level;
        result["score_breakdown"] = 
        {
            {"default", score.defaults},
            {"specific", score.specific},
            {"raw_specific", score.rawPoints}
        };
        result["top_threats"] = score.topThreats;
    }
    else
    {
        result["supported"] = false;
        result["score"] = -1;
    }

    
    result["details"] = details;

    std::cout << result.dump(4,' ', true, json::error_handler_t::replace);
    return 0;
}