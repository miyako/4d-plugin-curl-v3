#include <iostream>

extern "C" int proxy_user_relink_probe();

int main() {
    if (proxy_user_relink_probe() != 417) return 1;
    std::cout << "Relinked against the user-modified source library" << std::endl;
    return 0;
}
