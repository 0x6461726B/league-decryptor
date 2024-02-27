#pragma once
#include "framework.h"

std::vector<int> patternToByte(const char* pattern) {
    std::vector<int> bytes;
    while (*pattern) {
        if (*pattern == '?') {
            bytes.push_back(-1);
            pattern += (*pattern == '?') ? 2 : 1;
        }
        else {
            bytes.push_back(std::strtol(pattern, const_cast<char**>(&pattern), 16));
        }
    }
    return bytes;
}

static auto patternToByte2 = [](const char* pattern)
{
    auto bytes = std::vector<int>{};
    char* start = const_cast<char*>(pattern);
    char* end = const_cast<char*>(pattern) + strlen(pattern);

    for (char* current = start; current < end; ++current)
    {
        if (*current == '?')
        {
            ++current;
            if (*current == '?')
                ++current;
            bytes.push_back(-1);
        }
        else
            bytes.push_back(strtoul(current, &current, 16));
    }
    return bytes;
};