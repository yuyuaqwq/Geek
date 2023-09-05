#ifndef RING_QUEUE_H_
#define RING_QUEUE_H_

template<class T>
class RingQueue {
public:
    RingQueue(size_t count) : arr_(count) {
        head_ = 0;
        tail_ = 0;
    }

    bool IsEmpty() {
        return head_ == tail_;
    }

    bool IsFull() {
        return (tail_ + 1) % arr_.size() == tail_;
    }

    size_t Size() {
        if (tail_ >= head_) return tail_ - head_;
        return (tail_) + (arr_.size() - head_);
    }

    bool Enqueue(T&& t) {
        if (IsFull()) {
            return false;
        }
        arr_[tail_] = std::move(t);
        tail_ = (tail_ + 1) % arr_.size();
    }

    // 没有考虑异常安全
    T Dequeue() {
        if (IsEmpty()) {
            throw std::runtime_error("queue is empty.");
        }
        auto ret = std::move(arr_[head_]);
        head_ = (head_ + 1) % arr_.size();
        return ret;
    }

private:
    std::vector<T> arr_;
    size_t head_;
    size_t tail_;
};

#endif  // RING_QUEUE_H_