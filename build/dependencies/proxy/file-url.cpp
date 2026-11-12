#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include "url.hpp"

static void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

int main(int argc, char** argv) {
    try {
        require(argc == 2, "expected local PAC fixture path");
        using libproxy::url;
#ifdef _WIN32
        require(url("file:///E:/dir/file.pac").get_path() == "E:\\dir\\file.pac", "drive-letter path");
        require(url("file://server/share/file.pac").get_path() == "\\\\server\\share\\file.pac", "UNC path");
        require(url("pac+file:///E:/dir/file.pac").get_path() == "E:\\dir\\file.pac", "PAC file scheme");
        require(url("file://localhost/E:/dir/file.pac").get_path() == "E:\\dir\\file.pac", "localhost path");
        const std::string local_url = std::string("file:///") + argv[1];
#else
        require(url("file:///E:/dir/file.pac").get_path() == "/E:/dir/file.pac", "unchanged POSIX path");
        const std::string local_url = std::string("file://") + argv[1];
#endif
        require(url("https://server/dir/file.pac").get_path() == "/dir/file.pac", "HTTP path unchanged");
        std::ifstream input(argv[1]);
        require(input.is_open(), "open PAC fixture");
        const std::string expected((std::istreambuf_iterator<char>(input)),
            std::istreambuf_iterator<char>());
        for (const auto& prefix : {std::string(""), std::string("pac+")}) {
            url source(prefix + local_url);
            char* pac = source.get_pac();
            require(pac != NULL, "read local PAC through source library");
            const std::string actual(pac);
            delete[] pac;
            require(actual == expected, "local PAC contents");
        }
        std::cout << "file/PAC paths and local file contents verified" << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << std::endl;
        return 1;
    }
}
