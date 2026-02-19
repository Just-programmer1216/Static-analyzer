#include "../include/scoreVB.hpp"

#include <cmath>
#include <algorithm>
#include <vector>
#include <string>

static int convertToPointsVB(int sev)
{
    const int pmax = 40;

    const double x = static_cast<double>(sev) / 10.0;
    const double val = static_cast<double>(pmax) * (x * x);

    int pts = static_cast<int>(std::lround(val));
    return pts;
}

static int saturateExpVB(int raw, int budget, double k)
{
    if (budget <= 0) return 0;
    if (raw <= 0) return 0;

    const double dBudget = static_cast<double>(budget);
    const double score = dBudget * (1.0 - std::exp(-static_cast<double>(raw) / k));

    int out = static_cast<int>(std::lround(score));
    return out;
}

static int computeDefaultVB(const json& defaultChecks)
{
    int score = 0;

    if (defaultChecks["extension_mismatch"]["found"].get<bool>())
        score += 15;

    if (defaultChecks["double_extension"]["found"].get<bool>())
        score += 15;

    if (defaultChecks["entropy"]["too_high"].get<bool>())
        score += 10;

    return score;
}

struct ThreatVB
{
    std::string category;
    std::string pattern;
    int severity = 0;
    int points = 0;
};

static void topThreatsVB(const json& signals, json& topThreats)
{
    std::vector<ThreatVB> list;
    list.reserve(static_cast<std::size_t>(signals.size()));

    for (const auto& s : signals)
    {
        ThreatVB t;
        t.category = s["category"].get<std::string>();
        t.pattern = s["pattern"].get<std::string>(); 
        t.severity = s["severity"].get<int>();
        t.points = convertToPointsVB(t.severity);
        list.push_back(std::move(t));
    }

    std::sort(list.begin(), list.end(),
        [](const ThreatVB& a, const ThreatVB& b)
        {
            return (a.points != b.points)
            ? (a.points > b.points)
            : (a.severity > b.severity);
        });

    topThreats = json::array();

    const std::size_t TOP_N = 5;
    for (std::size_t i = 0; i < list.size() && i < TOP_N; ++i)
    {
        json t;
        t["category"] = list[i].category;
        t["pattern"] = list[i].pattern; 
        t["severity"] = list[i].severity;
        t["points"] = list[i].points;
        topThreats.push_back(std::move(t));
    }
}

static int computeRawSpecificVB(const json& signals)
{
    int rawTotal = 0;
    int rawStructure = 0;

    for (const auto& s : signals)
    {
        const std::string category = s["category"].get<std::string>();
        const int sev = s["severity"].get<int>();
        const int pts = convertToPointsVB(sev);

        if (category == "structure_warning")
        {
            if (rawStructure >= 60)
                continue;

            int add = pts;
            if (rawStructure + add > 60)
                add = 60 - rawStructure;

            rawStructure += add;
            rawTotal += add;
            continue;
        }

        rawTotal += pts;
    }

    return rawTotal;
}

static std::string levelVB(int total)
{
    if (total <= 25) return "safe";
    if (total <= 55) return "medium";
    if (total <= 85) return "high";
    return "critical";
}

ScoreVB computeScoreVB(const json& defaultChecks, const json& specificCheck)
{
    ScoreVB score;
    int specificBudget = (defaultChecks["extension_mismatch"]["magic"].get<std::string>() == "unknown") ? 75 : 60;
    score.defaults = computeDefaultVB(defaultChecks);

    const json& signals = specificCheck["signals"];

    topThreatsVB(signals, score.topThreats);
    score.rawPoints = computeRawSpecificVB(signals);

    const double K = 120.0 / std::log(10.0); 
    score.specific = saturateExpVB(score.rawPoints, specificBudget, K);

    score.total = score.defaults + score.specific;
    score.level = levelVB(score.total);
    return score;
}