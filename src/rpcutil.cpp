// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018-2019 The SwiftCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcutil.h"
#include "rpcserver.h"
#include "rpcclient.h"
#include "util.h"

UniValue CallRPC(std::string args, std::string wallet)
{
    if (args.empty())
      throw std::runtime_error("No input.");

    std::vector<std::string> vArgs;

    bool fInQuotes = false;
    std::string s;
    for (size_t i = 0; i < args.size(); ++i)
    {
        char c = args[i];
        if (!fInQuotes
            && (c == ' ' || c == '\t'))
        {
            if (s.empty()) continue; // trim whitespace
            vArgs.push_back(part::TrimQuotes(s));
            s.clear();
            continue;
        };

        if (c == '"' && (i == 0 || args[i-1] != '\\'))
            fInQuotes = !fInQuotes;

        s.push_back(c);
    };
    if (!s.empty())
        vArgs.push_back(part::TrimQuotes(s));


    std::string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    UniValue params = RPCConvertValues(strMethod, vArgs);

    return tableRPC.execute(strMethod, params);
}
