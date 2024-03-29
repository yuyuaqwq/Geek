#ifndef RING_QUEUE_H_
#define RING_QUEUE_H_

#include <exception>
#include <atomic>

/*
* 无锁单读单写循环队列
* 参考：https://zhuanlan.zhihu.com/p/360872276
*/

template<class T>
class RingQueue {
public:
    RingQueue(T* arr, size_t count) {
        Reset(arr, count);
    }

    void Reset(T* arr, size_t count) {
        if ((count > 0) && (count & (count - 1)) != 0) {
            throw std::runtime_error("must be a power of 2.");
        }
        arr_ = arr;
        count_ = count;
        head_ = 0;
        tail_ = 0;
    }

    bool IsEmpty() {
        return head_.load() == tail_.load();
    }

    bool IsFull() {
        return RewindIndex(tail_.load() + 1) == tail_.load();
    }

    size_t Size() {
        if (tail_.load() >= head_.load()) {
            return tail_.load() - head_.load();
        }
        return (tail_.load()) + (count_ - head_.load());
    }

    bool Enqueue(T&& ele) {
        auto ctail = tail_.load(std::memory_order_relaxed);
        auto ntail = RewindIndex(ctail + 1);
        if (ntail != head_.load(std::memory_order_acquire)) {
            arr_[tail_] = std::move(ele);
            tail_.store(ntail, std::memory_order_release);
            return true;
        }
        return false;
    }

    bool Dequeue(T* ele) {
        auto chead = head_.load(std::memory_order_relaxed);
        if (chead != tail_.load(std::memory_order_acquire)) {
            *ele = std::move(arr_[head_]);
            head_.store(RewindIndex(chead + 1), std::memory_order_release);
            return true;
        }
        return false;
    }

private:
	size_t RewindIndex(size_t i) {
        return i & (count_ - 1);
    }

private:
    T* arr_;
    size_t count_;
    std::atomic<size_t> head_;
    std::atomic<size_t> tail_;
};

#endif  // RING_QUEUE_H_