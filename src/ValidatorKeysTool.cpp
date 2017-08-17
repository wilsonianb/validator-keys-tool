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

#include <ValidatorKeysTool.h>
#include <ValidatorKeys.h>
#include <ripple/beast/core/LexicalCast.h>
#include <ripple/beast/core/PlatformConfig.h>
#include <ripple/beast/core/SemanticVersion.h>
#include <ripple/beast/unit_test.h>
#include <beast/unit_test/dstream.hpp>
#include <boost/format.hpp>
#include <boost/program_options.hpp>

//------------------------------------------------------------------------------
char const* const versionString =

    //--------------------------------------------------------------------------
    //  The build version number. You must edit this for each release
    //  and follow the format described at http://semver.org/
    //
        "0.2.0"

#if defined(DEBUG) || defined(SANITIZER)
       "+"
#ifdef DEBUG
        "DEBUG"
#ifdef SANITIZER
        "."
#endif
#endif

#ifdef SANITIZER
        BEAST_PP_STR1_(SANITIZER)
#endif
#endif

    //--------------------------------------------------------------------------
    ;

static int runUnitTests ()
{
    using namespace beast::unit_test;
    beast::unit_test::dstream dout{std::cout};
    reporter r{dout};
    bool const anyFailed = r.run_each(global_suites());
    if(anyFailed)
        return EXIT_FAILURE;    //LCOV_EXCL_LINE
    return EXIT_SUCCESS;
}

void createManifest (
    std::string const& masterSecretKey,
    std::string const& secretKey,
    std::uint32_t const& sequence)
{
    using namespace ripple;

    ValidatorKeys const keys (masterSecretKey, KeyType::ed25519);

    auto const manifest = keys.createManifest (secretKey, KeyType::ed25519, sequence);

    if (! manifest)
        throw std::runtime_error ("Unable to create manifest.\n");

    std::cout << *manifest << std::endl << std::endl;
}

void createRevocation (std::string const& masterSecretKey)
{
    using namespace ripple;

    ValidatorKeys const keys (masterSecretKey, KeyType::ed25519);

    auto const revocation = keys.revoke ();

    std::cout << "Master public key:\n" << strHex(keys.publicKey()) << "\n\n";
    std::cout << "[validator_key_revocation]\n";

    std::cout << revocation << std::endl << std::endl;
}

void signData (std::string const& secretKey, std::string const& data)
{
    using namespace ripple;

    if (data.empty())
        throw std::runtime_error (
            "Syntax error: Must specify data string to sign");

    ValidatorKeys const keys (secretKey, KeyType::ed25519);

    std::cout << keys.sign (data) << std::endl;
    std::cout << std::endl;
}

int runCommand (std::string const& command,
    std::vector <std::string> const& args)
{
    using namespace std;

    static map<string, vector<string>::size_type> const commandArgs = {
        { "authorize_key", 3 },
        { "revoke_key", 1 },
        { "sign", 2 }};

    auto const iArgs = commandArgs.find (command);

    if (iArgs == commandArgs.end ())
        throw std::runtime_error ("Unknown command: " + command);

    if (args.size() != iArgs->second)
        throw std::runtime_error ("Syntax error: Wrong number of arguments");

    if (command == "authorize_key")
    {
        std::uint32_t sequence;
        try {
            sequence = beast::lexicalCastThrow <std::uint32_t> (args[2]);
        } catch (std::exception const&) {
            throw std::runtime_error ("Sequence must be a number");
        }
        createManifest (args[0], args[1], sequence);
    }
    else if (command == "revoke_key")
        createRevocation (args[0]);
    else if (command == "sign")
        signData (args[0], args[1]);

    return 0;
}

//LCOV_EXCL_START
void printHelp (const boost::program_options::options_description& desc)
{
    std::cerr
        << "validator-keys [options] <command> [<argument> ...]\n"
        << desc << std::endl
        << "Commands: \n"
           "     authorize_key <masterkey> <key> <seq> Authorize key with master key.\n"
           "     revoke_key <masterkey>                Revoke master key.\n"
           "     sign <key> <data>                     Sign string with key.\n";
}
//LCOV_EXCL_STOP

std::string const&
getVersionString ()
{
    static std::string const value = [] {
        std::string const s = versionString;
        beast::SemanticVersion v;
        if (!v.parse (s) || v.print () != s)
            throw std::logic_error (s + ": Bad version string"); //LCOV_EXCL_LINE
        return s;
    }();
    return value;
}

int main (int argc, char** argv)
{
#if defined(__GNUC__) && !defined(__clang__)
    auto constexpr gccver = (__GNUC__ * 100 * 100) +
                            (__GNUC_MINOR__ * 100) +
                            __GNUC_PATCHLEVEL__;

    static_assert (gccver >= 50100,
        "GCC version 5.1.0 or later is required to compile validator-keys.");
#endif

    static_assert (BOOST_VERSION >= 105700,
        "Boost version 1.57 or later is required to compile validator-keys");

    namespace po = boost::program_options;

    po::variables_map vm;

    // Set up option parsing.
    //
    po::options_description general ("General Options");
    general.add_options ()
    ("help,h", "Display this message.")
    ("unittest,u", "Perform unit tests.")
    ("version", "Display the build version.")
    ;

    po::options_description hidden("Hidden options");
    hidden.add_options()
    ("command", po::value< std::string > (), "Command.")
    ("arguments",po::value< std::vector<std::string> > ()->default_value(
        std::vector <std::string> (), "empty"), "Arguments.")
    ;
    po::positional_options_description p;
    p.add ("command", 1).add ("arguments", -1);

    po::options_description cmdline_options;
    cmdline_options.add(general).add(hidden);

    // Parse options, if no error.
    try
    {
        po::store (po::command_line_parser (argc, argv)
            .options (cmdline_options)    // Parse options.
            .positional (p)
            .run (),
            vm);
        po::notify (vm);                  // Invoke option notify functions.
    }
    //LCOV_EXCL_START
    catch (std::exception const&)
    {
        std::cerr << "validator-keys: Incorrect command line syntax." << std::endl;
        std::cerr << "Use '--help' for a list of options." << std::endl;
        return EXIT_FAILURE;
    }
    //LCOV_EXCL_STOP

    // Run the unit tests if requested.
    // The unit tests will exit the application with an appropriate return code.
    if (vm.count ("unittest"))
        return runUnitTests();

    //LCOV_EXCL_START
    if (vm.count ("version"))
    {
        std::cout << "validator-keys version " <<
            getVersionString () << std::endl;
        return 0;
    }

    if (vm.count ("help") || ! vm.count ("command"))
    {
        printHelp (general);
        return EXIT_SUCCESS;
    }

    try
    {
        return runCommand (
            vm["command"].as<std::string>(),
            vm["arguments"].as<std::vector<std::string>>());
    }
    catch(std::exception const& e)
    {
        std::cerr << e.what() << "\n";
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
    //LCOV_EXCL_STOP
}
