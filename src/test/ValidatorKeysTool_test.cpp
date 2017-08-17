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

#include <ValidatorKeysTool.h>
#include <ValidatorKeys.h>
#include <ripple/beast/unit_test.h>
#include <ripple/protocol/SecretKey.h>

namespace ripple {

namespace tests {

class ValidatorKeysTool_test : public beast::unit_test::suite
{
private:

    // Allow cout to be redirected.  Destructor restores old cout streambuf.
    class CoutRedirect
    {
    public:
        CoutRedirect (std::stringstream& sStream)
        : old_ (std::cout.rdbuf (sStream.rdbuf()))
        { }

        ~CoutRedirect()
        {
            std::cout.rdbuf (old_);
        }

    private:
        std::streambuf* const old_;
    };

    void
    testCreateManifest ()
    {
        testcase ("Create manifest");

        std::stringstream coutCapture;
        CoutRedirect coutRedirect {coutCapture};

        auto testManifest = [this](
            std::string const& masterSecretKey,
            std::string const& secretKey,
            std::uint32_t const& sequence,
            std::string const& expectedError)
        {
            try
            {
                createManifest (masterSecretKey, secretKey, sequence);
                BEAST_EXPECT(expectedError.empty());
            }
            catch (std::exception const& e)
            {
                BEAST_EXPECT(e.what() == expectedError);
            }
        };

        {
            std::string const expectedError = "";
            testManifest (
                randomSecretKey().to_string(),
                randomSecretKey().to_string(),
                1,
                expectedError);
        }
    }

    void
    testCreateRevocation ()
    {
        testcase ("Create Revocation");

        std::stringstream coutCapture;
        CoutRedirect coutRedirect {coutCapture};

        createRevocation (randomSecretKey().to_string());
    }

    void
    testSign ()
    {
        testcase ("Sign");

        std::stringstream coutCapture;
        CoutRedirect coutRedirect {coutCapture};

        auto testSign = [this](
            std::string const& secretKey,
            std::string const& data,
            std::string const& expectedError)
        {
            try
            {
                signData (secretKey, data);
                BEAST_EXPECT(expectedError.empty());
            }
            catch (std::exception const& e)
            {
                BEAST_EXPECT(e.what() == expectedError);
            }
        };

        std::string const secretKey =
            randomSecretKey().to_string();
        std::string const data = "data to sign";

        {
            std::string const emptyData = "";
            std::string const expectedError =
                "Syntax error: Must specify data string to sign";
            testSign (secretKey, emptyData, expectedError);
        }
        {
            std::string const expectedError = "";
            testSign (secretKey, data, expectedError);
        }
    }

    void
    testRunCommand ()
    {
        testcase ("Run Command");

        std::stringstream coutCapture;
        CoutRedirect coutRedirect {coutCapture};

        auto testCommand = [this](
            std::string const& command,
            std::vector <std::string> const& args,
            std::string const& expectedError)
        {
            try
            {
                runCommand (command, args);
                BEAST_EXPECT(expectedError.empty());
            }
            catch (std::exception const& e)
            {
                BEAST_EXPECT(e.what() == expectedError);
            }
        };

        std::string const masterSecretKey =
            randomSecretKey().to_string();
        std::string const secretKey =
            randomSecretKey().to_string();
        std::vector <std::string> const noArgs;
        std::vector <std::string> const oneArg = { "data" };
        std::vector <std::string> const twoArgs = { "more", "data" };
        std::vector <std::string> const threeArgs = { "even", "more", "data" };
        std::vector <std::string> const fourArgs = { "way", "too", "much", "data" };
        std::string const noError = "";
        std::string const argError = "Syntax error: Wrong number of arguments";
        {
            std::string const command = "unknown";
            std::string const expectedError = "Unknown command: " + command;
            testCommand (command, noArgs, expectedError);
            testCommand (command, oneArg, expectedError);
            testCommand (command, twoArgs, expectedError);
            testCommand (command, threeArgs, expectedError);
            testCommand (command, fourArgs, expectedError);
        }
        {
            std::string const command = "authorize_key";
            testCommand (command, noArgs, argError);
            testCommand (command, oneArg, argError);
            testCommand (command, twoArgs, argError);
            testCommand (command, fourArgs, argError);

            std::string const expectedError = "Sequence must be a number";
            testCommand (command, {masterSecretKey, secretKey, "not a number"}, expectedError);

            testCommand (command, {masterSecretKey, secretKey, "1"}, noError);
        }
        {
            std::string const command = "revoke_key";
            testCommand (command, noArgs, argError);
            testCommand (command, twoArgs, argError);
            testCommand (command, threeArgs, argError);
            testCommand (command, fourArgs, argError);

            testCommand (command, {masterSecretKey}, noError);
        }
        {
            std::string const command = "sign";
            testCommand (command, noArgs, argError);
            testCommand (command, oneArg, argError);
            testCommand (command, threeArgs, argError);
            testCommand (command, fourArgs, argError);

            testCommand (command, {secretKey, "data"}, noError);
        }
    }

public:
    void
    run() override
    {
        getVersionString();

        testCreateManifest ();
        testCreateRevocation ();
        testSign ();
        testRunCommand ();
    }
};

BEAST_DEFINE_TESTSUITE(ValidatorKeysTool, keys, ripple);

} // tests

} // ripple
