#include "../../include/utils/addingVB.hpp"


void addingVB(json& signals, const std::string& category, const std::string& pattern, int severity)
{
    json item;
    
    item["category"] = category;
    item["pattern"] = pattern;
    item["severity"] = severity;

    signals.push_back(item);
}