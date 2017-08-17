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

#include <ripple/crypto/KeyType.h>
#include <ripple/protocol/SecretKey.h>

namespace ripple {

struct ValidatorToken
{
    std::string const manifest;
    SecretKey const secretKey;

    /// Returns base64-encoded JSON object
    std::string toString () const;
};

class ValidatorKeys
{
private:
    KeyType keyType_;
    PublicKey publicKey_;
    SecretKey secretKey_;

public:
    explicit
    ValidatorKeys (
        std::string const& secretKey,
        KeyType const& keyType);

    ~ValidatorKeys () = default;

    inline bool
    operator==(ValidatorKeys const& rhs) const
    {
        // TODO Compare secretKey_
        return keyType_ == rhs.keyType_ &&
            publicKey_ == rhs.publicKey_;
    }

    /** Returns base64-encoded manifest

        @param secretKey Hex-encoded secret key to be authorized
        @param keyType Key type for the authorized key
        @param sequence Sequence number of the authorization manifest
    */
    boost::optional<std::string>
    createManifest (
        std::string const& secretKey,
        KeyType const& keyType,
        std::uint32_t const& sequence) const;

    /** Revokes validator keys

        @return base64-encoded key revocation
    */
    std::string
    revoke () const;

    /** Signs string with validator key

    @param data String to sign

    @return hex-encoded signature
    */
    std::string
    sign (std::string const& data) const;

    /** Returns the public key. */
    PublicKey const&
    publicKey () const
    {
        return publicKey_;
    }
};

} // ripple
