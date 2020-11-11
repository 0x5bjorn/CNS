#include <iostream>

std::string decrypt(std::string msg, int shift) {

    std::string result = "";
    
    for (int i = 0; i < msg.length(); ++i) {
        
        if (msg[i] == ' ') {
            result += msg[i];
            continue;
        }
        
        if (isupper(msg[i]) ) {
            result += char( int(msg[i]-shift+'A')%26 + 'A' );
        }
        else {
            result += char( int(msg[i]-shift+'a')%26 + 'a' );
        }
    }

    return result;
}

int main() {
    
    std::string msg;
    int shift;
    
    std::cout << "Enter encrypted message: ";
    getline(std::cin, msg);
    std::cout << "\nShift: ";
    std::cin >> shift;
    std::cout << "\nDecrypted message: " << decrypt(msg, shift) << "\n"; 

    return 0;
}
