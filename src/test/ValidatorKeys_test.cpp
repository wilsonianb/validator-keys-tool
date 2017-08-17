//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright 2016 Ripple Labs Inc.

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
#include <ripple/beast/unit_test.h>
#include <ripple/protocol/HashPrefix.h>
#include <ripple/protocol/Sign.h>
#include <beast/core/detail/base64.hpp>

namespace ripple {

namespace tests {

class ValidatorKeys_test : public beast::unit_test::suite
{
private:
    std::array<KeyType, 2> const keyTypes {{
        KeyType::ed25519,
        KeyType::secp256k1 }};

    void
    testValidatorKeys ()
    {
        testcase ("Make Validator Keys");

        auto testBadKey = [this](
            std::string const& badSecret,
            KeyType const& keyType)
        {
            try
            {
                ValidatorKeys const impossibleKeys (badSecret, keyType);
                fail();
            }
            catch (std::exception const& e)
            {
                std::string const expectedError = "ValidatorKeys requires 32 byte hex-encoded secret key.";
                BEAST_EXPECT(e.what() == expectedError);
            }
        };

        for (auto const keyType : keyTypes)
        {
            auto const kp = randomKeyPair(keyType);

            ValidatorKeys const keys (kp.second.to_string(), keyType);

            BEAST_EXPECT (kp.first == keys.publicKey());

            {
                std::string const badSecret = "this is not a hex-encoded secret key";
                testBadKey (badSecret, keyType);
            }
            {
                std::string const badSecret = "ABC123";
                testBadKey (badSecret, keyType);
            }
        }
    }

    void
    testCreateManifest ()
    {
        testcase ("Create Manifest");

        for (auto const masterKeyType : keyTypes)
        {
            ValidatorKeys keys (
                randomSecretKey ().to_string(),
                masterKeyType);
            std::uint32_t sequence = 5;

            for (auto const keyType : keyTypes)
            {
                auto const kp = randomKeyPair (keyType);

                auto const manifest = keys.createManifest (kp.second.to_string(), keyType, sequence);

                if (! BEAST_EXPECT(manifest))
                    continue;

                STObject st (sfGeneric);
                auto const m = beast::detail::base64_decode(*manifest);
                SerialIter sit (m.data (), m.size ());
                st.set (sit);

                auto const seq = get (st, sfSequence);
                BEAST_EXPECT (seq);
                BEAST_EXPECT (*seq == sequence);

                auto const tpk = get<PublicKey>(st, sfSigningPubKey);
                BEAST_EXPECT (tpk);
                BEAST_EXPECT (*tpk == kp.first);
                BEAST_EXPECT (verify (st, HashPrefix::manifest, kp.first));

                auto const pk = get<PublicKey>(st, sfPublicKey);
                BEAST_EXPECT (pk);
                BEAST_EXPECT (*pk == keys.publicKey ());
                BEAST_EXPECT (verify (
                    st, HashPrefix::manifest, keys.publicKey (),
                    sfMasterSignature));

                BEAST_EXPECT(! keys.createManifest (kp.second.to_string(), keyType,
                    std::numeric_limits<std::uint32_t>::max ()));
                {
                    std::string const badSecret = "this is not a hex-encoded secret key";
                    BEAST_EXPECT(! keys.createManifest (badSecret, keyType, sequence));
                }
                {
                    std::string const badSecret = "ABC123";
                    BEAST_EXPECT(! keys.createManifest (badSecret, keyType, sequence));
                }
            }
        }
    }

    void
    testRevoke ()
    {
        testcase ("Revoke");

        for (auto const keyType : keyTypes)
        {
            ValidatorKeys keys (
                randomKeyPair(keyType).second.to_string(),
                keyType);

            auto const revocation = keys.revoke ();

            STObject st (sfGeneric);
            auto const manifest = beast::detail::base64_decode(revocation);
            SerialIter sit (manifest.data (), manifest.size ());
            st.set (sit);

            auto const seq = get (st, sfSequence);
            BEAST_EXPECT (seq);
            BEAST_EXPECT (*seq == std::numeric_limits<std::uint32_t>::max ());

            auto const pk = get (st, sfPublicKey);
            BEAST_EXPECT (pk);
            BEAST_EXPECT (*pk == keys.publicKey ());
            BEAST_EXPECT (verify (
                st, HashPrefix::manifest, keys.publicKey (),
                sfMasterSignature));
        }
    }

    void
    testSign ()
    {
        testcase ("Sign");

        std::map<KeyType, std::string> expected({
            { KeyType::ed25519, "2EE541D6825791BF5454C571D2B363EAB3F01C73159B1F"
                "237AC6D38663A82B9D5EAD262D5F776B916E68247A1F082090F3BAE7ABC939"
                "C8F29B0DC759FD712300" },
            { KeyType::secp256k1, "3045022100F142C27BF83D8D4541C7A4E759DE64A672"
                "51A388A422DFDA6F4B470A2113ABC4022002DA56695F3A805F62B55E7CC8D5"
                "55438D64A229CD0B4BA2AE33402443B20409" }
        });

        std::string const data = "data to sign";

        for (auto const keyType : keyTypes)
        {
            auto const sk = generateSecretKey(keyType, generateSeed("test"));
            ValidatorKeys keys (sk.to_string(), keyType);

            auto const signature = keys.sign (data);
            BEAST_EXPECT(expected[keyType] == signature);

            auto const ret = strUnHex (signature);
            BEAST_EXPECT (ret.second);
            BEAST_EXPECT (ret.first.size ());
            BEAST_EXPECT (verify (
                keys.publicKey(),
                makeSlice (data),
                makeSlice (ret.first)));
        }
    }

public:
    void
    run() override
    {
        testValidatorKeys ();
        testCreateManifest ();
        testRevoke ();
        testSign ();
    }
};

BEAST_DEFINE_TESTSUITE(ValidatorKeys, keys, ripple);

} // tests

} // ripple
