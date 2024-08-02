#include <numeric>
#include <iostream>
#include <vector>
#include <cassert>

using namespace std;
int main()
{
    static const int VECTOR_SIZE = 8;
    vector<byte> flags = {byte(0x01), byte(0x02), byte(0x04), byte(0x08),
         byte(0x10), byte(0x20), byte(0x40), byte(0x80)};
    cout << "flags vector table lifted out of the loop at compile time" << endl;
    for (auto b: flags) {
        cout << "0x" << std::hex << (unsigned int)b << ", ";
    };
    cout << std::endl;

    assert(flags.size() == VECTOR_SIZE);
    std::vector<byte> prio = {byte(0), byte(1), byte(0),
         byte(3), byte(0), byte(5), byte(0), byte(7)};
    assert(prio.size() == VECTOR_SIZE);
    cout << "flags priority table passed at runtime as a function parameter" << endl;
    for (auto p: prio) {
        cout << "0x" << std::hex << (unsigned int)p << ", ";
    };
    cout << std::endl;

    std::vector<bool> mask(VECTOR_SIZE);
    std::vector<byte> active_flags(VECTOR_SIZE);
    for (int i = 0; i < VECTOR_SIZE; i++) {
        mask[i] = (prio[i] != byte(0)) ? true : false;
        active_flags[i] = mask[i] ? flags[i] : byte(0);
    }
    cout << "mask vector created from prio" << endl;
    for (auto p: mask) {
        cout << "0x" << std::hex << (bool)p << ", ";
    };
    cout << "active flags vector created from prio" << endl;
    for (auto a: active_flags) {
        cout << "0x" << std::hex << (unsigned int)a << ", ";
    };
    
    byte pfc_map = std::reduce(active_flags.begin(), active_flags.end(),
        *active_flags.begin(),
        [](byte a, byte b){return a|b;});
    cout << "result = 0x" << std::hex << (unsigned int)pfc_map << std::endl;

}