#ifndef ENDIAN_LE_VB_HPP
#define ENDIAN_LE_VB_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

bool readU16LEVB(const std::vector<unsigned char>& buffer, std::size_t offset, std::uint16_t& out);

bool readU32LEVB(const std::vector<unsigned char>& buffer, std::size_t offset, std::uint32_t& out);

#endif
