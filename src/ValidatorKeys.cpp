//------------------------------------------------------------------------------
/*
    This file is part of validator-keys-tool:
        https://github.com/ripple/validator-keys-tool
    Copyright (c) 2016 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#include <ValidatorKeys.h>
#include <ripple/basics/StringUtilities.h>
#include <ripple/protocol/HashPrefix.h>
#include <ripple/protocol/Sign.h>
#include <beast/core/detail/base64.hpp>
#include <fstream>

namespace ripple {

ValidatorKeys::ValidatorKeys (
    std::string const& secretKey,
    KeyType const& keyType)
    : keyType_ (keyType)
{
    auto const ret = strUnHex (secretKey);
    if (! ret.second || ret.first.size () != 32)
        throw std::runtime_error (
            "ValidatorKeys requires 32 byte hex-encoded secret key.");

    secretKey_ = SecretKey(Slice{ ret.first.data (), ret.first.size() });
    publicKey_ = derivePublicKey(keyType, secretKey_);
}

boost::optional<std::string>
ValidatorKeys::createManifest (
    std::string const& secretKey,
    KeyType const& keyType,
    std::uint32_t const& sequence) const
{
    auto const ret = strUnHex (secretKey);
    if (std::numeric_limits<std::uint32_t>::max () - 1 <= sequence ||
            ! ret.second || ret.first.size () != 32)
        return boost::none;

    SecretKey const sk (Slice{ ret.first.data (), ret.first.size() });
    auto const pk = derivePublicKey(keyType, sk);

    STObject st(sfGeneric);
    st[sfSequence] = sequence;
    st[sfPublicKey] = publicKey_;
    st[sfSigningPubKey] = pk;

    ripple::sign(st, HashPrefix::manifest, keyType, sk);

    ripple::sign(st, HashPrefix::manifest, keyType_, secretKey_,
        sfMasterSignature);

    Serializer s;
    st.add(s);

    std::string m (static_cast<char const*> (s.data()), s.size());
    return beast::detail::base64_encode(m);
}

std::string
ValidatorKeys::revoke () const
{
    STObject st(sfGeneric);
    st[sfSequence] = std::numeric_limits<std::uint32_t>::max ();
    st[sfPublicKey] = publicKey_;

    ripple::sign(st, HashPrefix::manifest, keyType_, secretKey_,
        sfMasterSignature);

    Serializer s;
    st.add(s);

    std::string m (static_cast<char const*> (s.data()), s.size());
    return beast::detail::base64_encode(m);
}

std::string
ValidatorKeys::sign (std::string const& data) const
{
    return strHex(ripple::sign (publicKey_, secretKey_, makeSlice (data)));
}

} // ripple
