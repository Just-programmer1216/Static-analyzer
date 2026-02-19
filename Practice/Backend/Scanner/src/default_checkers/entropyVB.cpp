#include "../../include/default_checkers/entropyVB.hpp"

#include <array>
#include <cmath>

double calcEntropyRangeVB(const std::vector<unsigned char>& buffer, std::size_t offset, std::size_t length)
{
    if (buffer.empty()|| offset >= buffer.size())
        return 0.0;

    const std::size_t avail = buffer.size() - offset;
    const std::size_t n = (length > avail) ? avail : length;

    if(n == 0)
        return 0.0;

    std::array<std::size_t, 256> freq{};
    freq.fill(0);

    for (std::size_t i = 0; i < n; ++i)
        freq[buffer[offset + i]]++;

    const double total = static_cast<double>(buffer.size());
    double entropy = 0.0;

    for (std::size_t count : freq)
    {
        if (count == 0) continue;
        double p = static_cast<double>(count) / total;
        entropy -= p * std::log2(p);
    }

    return entropy;
}

static double calcEntropyVB(const std::vector<unsigned char>& buffer)
{
    return calcEntropyRangeVB(buffer, 0, buffer.size());
}

static double getThresholdVB(const std::string& logicalType)
{
    if (logicalType == "text" || logicalType == "script")
        return 6.0;

    if (logicalType == "pe")
        return 7.2;

    if (logicalType == "pdf")
        return 7.6;

    if (logicalType == "image")
        return 7.8;

    if (logicalType == "zip" || logicalType == "office")
        return 7.9;

    return 7.5;
}


json checkEntropyVB(const FileInfoVB& info, const std::vector<unsigned char>& buffer)
{
    json result;

    double entropy = calcEntropyVB(buffer);
    double threshold = getThresholdVB(info.logicalType);

    result["value"] = entropy;
    result["threshold"] = threshold;
    result["too_high"] = (entropy >= threshold);

    return result;
}
