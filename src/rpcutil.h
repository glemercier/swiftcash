// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018-2019 The SwiftCash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SWIFTCASH_RPCUTIL_H
#define SWIFTCASH_RPCUTIL_H

#include <univalue.h>
#include <string>

UniValue CallRPC(std::string args, std::string wallet);

#endif // SWIFTCASH_RPCUTIL_H

