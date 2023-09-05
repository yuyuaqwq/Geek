#ifndef TS_RING_QUEUE_H_
#define TS_RING_QUEUE_H_

#include <mutex>

#include <ring_queue.hpp>

template<class T>
class TsRingQueue : private RingQueue<T> {
public:
    TsRingQueue(size_t count) : RingQueue<T>(count) {

    }

    bool IsEmpty() {
        std::lock_guard<std::mutex> guard(lock_);
        return RingQueue<T>::IsEmpty();
    }

    bool IsFull() {
        std::lock_guard<std::mutex> guard(lock_);
        return RingQueue<T>::IsFull();
    }

    size_t Size() {
        std::lock_guard<std::mutex> guard(lock_);
        return RingQueue<T>::Size();
    }

    bool Enqueue(T&& t) {
        std::lock_guard<std::mutex> guard(lock_);
        return RingQueue<T>::Enqueue();
    }

    // 没有考虑异常安全
    T Dequeue() {
        std::lock_guard<std::mutex> guard(lock_);
        return RingQueue<T>::Dequeue();
    }

private:
    std::mutex lock_;
};


#endif // TS_RING_QUEUE_H_