#pragma once

#include <stdexcept>
#include <atomic>
#include <cstddef>
#include <type_traits>
#include <utility>
#include <vector>
#include <new>

#define CACHELINE_SIZE 64

//
//   Lock-free Single-Producer Single-Consumer (SPSC) Ring Buffer
//   - Generic type accepted
//   - Thread safe
//

template <typename T>
class SPSCRingBuffer {

    // Static assertions for type constraints
    static_assert(!std::is_reference_v<T>, "SPSCRingBuffer does not support reference types.");

    // The buffer cannot be copied or moved
    SPSCRingBuffer(const SPSCRingBuffer&) = delete;
    SPSCRingBuffer& operator=(const SPSCRingBuffer&) = delete;
    SPSCRingBuffer(SPSCRingBuffer&&) = delete;
    SPSCRingBuffer& operator=(SPSCRingBuffer&&) = delete;


public:

    struct Slot {
        std::aligned_storage_t<sizeof(T), alignof(T)> storage;

        T* ptr() noexcept {
            return std::launder(reinterpret_cast<T*>(&storage));
        }
    };

    // Constructor and Destructor
    explicit SPSCRingBuffer(std::size_t capacity) :
        buffer(capacity), 
        buf_size(capacity),
        buffer_mask(capacity - 1), 
        write_idx(0),
        read_idx(0) 
    {
        if (!valid_capacity(capacity)) { 
            throw std::invalid_argument("Capacity must be a power of two."); 
        }
    }
    
    ~SPSCRingBuffer() {
        std::size_t read = read_idx.load(std::memory_order_relaxed); 
        std::size_t write = write_idx.load(std::memory_order_relaxed);

        while (read != write) { 
            T* p = buffer[read].ptr(); 
            p->~T(); 
            read = next_index(read); 
        }
    }


    //  Producer API
    bool push(const T& val) {
        std::size_t cur = write_idx.load(std::memory_order_relaxed); 
        std::size_t next = next_index(cur);         
        if(next == read_idx.load(std::memory_order_acquire))  return false; 

        new (buffer[cur].ptr()) T(val);

        write_idx.store(next, std::memory_order_release); 
        return true; 
    }


    template <typename... Args> 
    bool try_emplace(Args&&... args) {
        std::size_t cur = write_idx.load(std::memory_order_relaxed);
        std::size_t next = next_index(cur);  
        if(next == read_idx.load(std::memory_order_acquire))  return false; 

        new (buffer[cur].ptr()) T(std::forward<Args>(args)...); 

        write_idx.store(next, std::memory_order_release); 
        return true; 
    }

    // Consumer API
    bool pop(T& res) {
        std::size_t cur = read_idx.load(std::memory_order_relaxed);
        if(empty()) return false;

        T* temp_ptr = buffer[cur].ptr(); 
        res = std::move(*temp_ptr);
        temp_ptr->~T();   // free memory location after popping

        read_idx.store(next_index(cur), std::memory_order_release);
        return true; 
    }

    std::size_t capacity() const noexcept { 
        return buf_size; 
    }

    bool empty() const noexcept {
        return write_idx.load(std::memory_order_acquire) == read_idx.load(std::memory_order_acquire); 
    }

    bool full() const noexcept {
        std::size_t next_write = next_index(write_idx.load(std::memory_order_relaxed)); 
        return next_write == read_idx.load(std::memory_order_acquire); 
    }



private:
    std::vector<Slot> buffer;
    std::size_t buf_size; 
    std::size_t buffer_mask;
    alignas(CACHELINE_SIZE) std::atomic<std::size_t> write_idx;
    alignas(CACHELINE_SIZE) std::atomic<std::size_t> read_idx;

    // Helpers
    std::size_t next_index(std::size_t idx) const noexcept {
        return (idx + 1) & buffer_mask; 
    }

    static bool valid_capacity(std::size_t val) noexcept {
        return val != 0 && (val & (val - 1)) == 0;
    }

};  