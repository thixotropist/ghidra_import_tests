#include <vector>
#include <iostream>
typedef std::vector<std::vector<float>> vector_2d ;

void output_txt(vector_2d* new_data, vector_2d* data) {
    std::cout << "data outer dimension:" << data->size() << "\n";
    std::cout <<  "data[0] inner dimension:" << data->begin()->size() << "\n";
    new (new_data) std::vector<std::vector<float>>(data);
    return;
}