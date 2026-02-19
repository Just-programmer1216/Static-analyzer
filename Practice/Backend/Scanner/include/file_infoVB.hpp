#ifndef FILE_INFO_VB_HPP
#define FILE_INFO_VB_HPP

#include <string>
#include <vector>
#include "json.hpp"
#include "default_checkers/magicVB.hpp"

using json = nlohmann::json;

struct FileInfoVB 
{
    std::string filename;
    std::string extension;
    std::string magicType;
    std::string logicalType;
    std::size_t size = 0;
};

bool readFileVB(const std::string& path, std::vector<unsigned char>& buffer);

std::string extractFilenameVB(const std::string& path);
std::string extractExtVB(const std::string& filename);

bool isProbablyTextVB(const std::vector<unsigned char>& buffer);

std::string fileTypeVB(const std::string& magic, const std::string& extension, const std::vector<unsigned char>& buffer);

FileInfoVB getFileInfoVB(const std::string& path, const std::vector<unsigned char>& buffer);

#endif