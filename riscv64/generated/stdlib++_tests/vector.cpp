#include <vector>
#include <iostream>

int main()
{
std::vector<float> a;
std::vector<float> b = {1.0, 2.0, 3.0};
std::cout << "b.front=" << b.front() << "\n";
std::cout << "b.back=" << b.back() << "\n";
std::cout << "b.data=" << b.data() << "\n";
std::cout << "b.capacity=" << b.capacity() << "\n";
b.resize(7);
std::cout << "b.data=" << b.data() << "\n";
std::cout << "b.capacity=" << b.capacity() << "\n";
std::cout << "a = b" << "\n";
a = b;
std::cout << "a.front=" << a.front() << "\n";
}

