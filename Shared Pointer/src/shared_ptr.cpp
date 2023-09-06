
#ifndef SHARED_PTR_H
#define SHARED_PTR_H

class Test_Type {
public:
    static bool deleted;
    Test_Type() {};
    ~Test_Type() { deleted = true; };
};
bool Test_Type::deleted = false;

class reference_counter {
public:
    reference_counter() : counter(0) {}
    void increase() { counter++; }
    void decrease() { counter--; }
    int get_counter() { return counter; }
private:
    int counter;
};

template <typename T>
class shared_ptr {
public:

    shared_ptr(T* input_ptr);
    ~shared_ptr();
    shared_ptr(const shared_ptr<T>& other);
    shared_ptr<T>& operator = (const shared_ptr<T>& other);
    shared_ptr(shared_ptr<T>&& other);
    shared_ptr<T>& operator = (shared_ptr<T>&& other);

    T* get();
    int use_count();

private:

    T* ptr;
    reference_counter* counter;

};

template<typename T>
shared_ptr<T>::shared_ptr(T* input_ptr) { 
    ptr = input_ptr;
    counter = new reference_counter;
    counter->increase();
}

template<typename T>
shared_ptr<T>::~shared_ptr() { 
    counter->decrease();
    if (counter->get_counter() == 0) {
        if (ptr != NULL) {
            delete ptr;
        }
        if (counter != NULL) {
            delete counter;
        }
    }
}

template<typename T>
shared_ptr<T>::shared_ptr(const shared_ptr<T>& other) {
    this->ptr = other.ptr;
    this->counter = other.counter;
    this->counter->increase();
}

template<typename T>
shared_ptr<T>& shared_ptr<T>::operator = (const shared_ptr<T>& other) {
    if (this != &other) {
        this->ptr = other.ptr;
        this->counter = other.counter;
        this->counter->increase();
    }
    return *this;
}

template<typename T>
shared_ptr<T>::shared_ptr(shared_ptr<T>&& other) {
    this->ptr = other.ptr;
    this->counter = other.counter;
    other.ptr = NULL;
    other.counter = NULL;
}

template<typename T>
shared_ptr<T>& shared_ptr<T>::operator = (shared_ptr<T>&& other) {
    if (this != &other) {
        this->ptr = other.ptr;
        this->counter = other.counter;
        other.ptr = NULL;
        other.counter = NULL;
    }
    return *this;
}

template<typename T>
T* shared_ptr<T>::get() {
    return ptr;
}

template<typename T>
int shared_ptr<T>::use_count() {
    return counter->get_counter();
}

#endif