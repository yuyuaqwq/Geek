#ifndef RING_QUEUE_H_
#define RING_QUEUE_H_

#include <Geek/sync/event.hpp>


template<class T, class Array = std::vector<T>>
class RingQueue {
public:
    RingQueue(sync::Event* readable_event = nullptr, sync::Event* writable_event = nullptr) {
        head_ = 0;
        tail_ = 0;
        readable_event_ = readable_event;
        writable_event_ = writable_event;

        wait_readable_ = false;
    }
    RingQueue(size_t count, sync::Event* readable_event = nullptr, sync::Event* writable_event = nullptr) : arr_(count) {
        head_ = 0;
        tail_ = 0;
        readable_event_ = readable_event;
        writable_event_ = writable_event;

        wait_readable_ = false;
    }

    void Reset(Array&& arr) {
        arr_ = std::move(arr);
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

    bool Enqueue(const T& t, bool full_wait = true) {
        _retry:
        if (IsFull()) {
            if (full_wait) {
                return false;
            }
            else {
                goto _retry;
            }
        }
        arr_[tail_] = t;
        tail_ = (tail_ + 1) % arr_.size();
        if (wait_readable_count_ > 0) {
            // 通知可读
            readable_event_->Set();
        }
    }

    void Enquene(T* buf, size_t count) {
        for (size_t i = 0; i < count; i++) {
            Enqueue(buf[i]);
        }
        //ptrdiff_t begin_pos, end_pos, cur_pos = 0;
        //do {
        //    if (tail_ >= head_) {
        //        begin_pos = tail_;
        //        end_pos = arr.size();
        //        tail_ = 0;
        //    }
        //    else {
        //        begin_pos = 0;
        //        end_pos = tail_;
        //    }
        //    size_t copy_count = end_pos - begin_pos;
        //    if (size < copy_count) {
        //        copy_count = size;
        //    }
        //    memcpy(&arr_[begin_pos], &buf[cur_pos], copy_count * sizeof(T));
        //    size -= copy_count;
        //    cur_pos += copy_count;
        //}  while (size > 0);
    }

    // 没有考虑异常安全
    T InternalDequeue(bool empty_wait = true) {
    _retry:
        if (IsEmpty()) {
            if (empty_wait) {
                lock_->Release();
                wait_readable_count_ = 1;
                readable_event_->Wait();
                wait_readable_count_ = 0;
                goto _retry;
            }
            else {
                throw std::runtime_error("queue is empty.");
            }
        }
        auto ret = std::move(arr_[head_]);
        head_ = (head_ + 1) % arr_.size();
        return ret;
    }

    T Dequeue(bool empty_wait = true) {
        lock_->Acquire();
        auto data = InternalDequeue(empty_wait);
        lock_->Release();
        return data;
    }

    void Dequeue(T* data, size_t count) {
        lock_->Acquire();
        for (size_t i = 0; i < count; i++) {
            data[i] = InternalDequeue();
        }
        lock_->Release();
    }

private:
    Array arr_;
    size_t head_;
    size_t tail_;
    sync::Mutex* lock_;
    sync::Event* readable_event_;
    sync::Event* writable_event_;

    size_t wait_readable_count_;
};

#endif  // RING_QUEUE_H_