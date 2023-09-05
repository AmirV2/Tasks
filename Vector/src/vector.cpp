
#ifndef VECTOR_H
#define VECTOR_H

#include <stdexcept> 

template <typename T>
class vector {
public:

    vector();

    ~vector();
    vector(const vector<T>& other);
    vector<T>& operator = (const vector<T>& other);
    vector(vector<T>&& other);
    vector<T>& operator = (vector<T>&& other);

    void push_back(T new_element);
    void pop_back();
    void resize(int new_size);
    int size();
    T& operator[](int index);
    bool operator==(const vector<T>& other);

private:

    void update_size(int new_size);
    int current_size;
    int max_size;
    T* list;

};

template<typename T>
vector<T>::vector() : current_size(0), max_size(1) { list = new T[max_size]; }

template<typename T>
vector<T>::~vector() { if (list != NULL) delete[] list; }

template<typename T>
vector<T>::vector(const vector<T>& other) {
    this->max_size = other.max_size;
    this->current_size = other.current_size;
    this->list = new T[this->max_size];
    for (int i = 0; i < this->current_size; i++) {
        this->list[i] = other.list[i];
    }
}

template<typename T>
vector<T>& vector<T>::operator = (const vector<T>& other) {
    if (this != &other) {

        this->max_size = other.max_size;
        this->current_size = other.current_size;

        if (this->list != NULL) delete[] this->list;
        this->list = new T[this->max_size];
        for (int i = 0; i < this->current_size; i++) {
            this->list[i] = other.list[i];
        }

    }
    return *this;
}

template<typename T>
vector<T>::vector(vector<T>&& other) {
    this->max_size = other.max_size;
    this->current_size = other.current_size;
    this->list = other->list;
    other->list = NULL;
}

template<typename T>
vector<T>& vector<T>::operator = (vector<T>&& other) {
    if (this != &other) {

        this->max_size = other.max_size;
        this->current_size = other.current_size;

        if (this->list != NULL) delete[] this->list;
        this->list = other->list;
        other->list = NULL;

    }
    return *this;
}

template<typename T>
void vector<T>::push_back(T new_element) {
    list[current_size] = new_element;
    current_size++;
    update_size(current_size);
}

template<typename T>
void vector<T>::pop_back() {
    current_size--;
    update_size(current_size);
}

template<typename T>
void vector<T>::resize(int new_size) {
    update_size(new_size);
}

template<typename T>
int vector<T>::size() {
    return current_size;
}

template<typename T>
T& vector<T>::operator[](int index) {
    if (index >= current_size) {
        throw std::out_of_range("Index out of range.");
    }
    return list[index];
}

template<typename T>
bool vector<T>::operator==(const vector<T>& other) {
    if (this->current_size != other.current_size) {
        return false;
    }
    for (int i = 0; i < this->current_size; i++) {
        if (!(this->list[i] == other.list[i])) {
            return false;
        }
    }
    return true;
}

template<typename T>
void vector<T>::update_size(int new_size) {
    if (new_size >= max_size) {
        while (new_size >= max_size) {
            max_size *= 2;
        }
        T* new_list = new T[max_size];
        for (int i = 0; i < current_size; i++) {
            new_list[i] = list[i];
        }
        delete[] list;
        list = new_list;
    }
    else if (new_size <= max_size / 4) {
        while (new_size <= max_size / 4) {
            max_size /= 2;
        }
        max_size = max_size == 0 ? 1 : max_size;
        T* new_list = new T[max_size];
        for (int i = 0; i < new_size; i++) {
            new_list[i] = list[i];
        }
        delete[] list;
        list = new_list;
    }
    current_size = new_size;
}

#endif
