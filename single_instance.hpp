#pragma once
template <class T>
class single_instance {
public:
    static inline T instance() { 
        static T obj;
        return obj;
    }
private:
    single_instance() = default;
    virtual ~single_instance() = default;
};