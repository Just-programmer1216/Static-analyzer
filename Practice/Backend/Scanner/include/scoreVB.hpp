#ifndef SCORE_VB_HPP
#define SCORE_VB_HPP

#include "json.hpp"
#include <string>

using json = nlohmann::json;

struct ScoreVB
{
    int total = 0;          
    int specific = 0;       
    int defaults = 0;       
    int rawPoints = 0;    
    json topThreats = json::array(); 
    std::string level;
};

ScoreVB computeScoreVB(const json& defaultChecks, const json& specificCheck);

#endif