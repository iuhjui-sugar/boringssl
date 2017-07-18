#ifndef OPENSSL_HEADER_SPAN_H
#define OPENSSL_HEADER_SPAN_H

#if defined(__cplusplus)
extern "C++" {

namespace bssl {

template <typename T>
class Span;

template <bool B, class T = void>
using enable_if_t = typename std::enable_if<B, T>::type;

namespace internal {
template <typename T>
class SpanBase {
  friend bool operator==(Span<T> lhs, Span<T> rhs) {
    return std::equal(lhs.begin(), lhs.end(), rhs.begin());
  }

  friend bool operator!=(Span<T> lhs, Span<T> rhs) {
    return !(lhs == rhs);
  }
};
}  // namespace internal

template <class T>
class Span : private internal::SpanBase<const T> {
 public:
  constexpr Span() : Span(nullptr, 0) {}
  constexpr Span(T *ptr, size_t len) : data_(ptr), size_(len) {}
  template <size_t N>
  constexpr Span(T (&array)[N]) : Span(array, N) {}

  template <typename Container,
            typename = enable_if_t<std::is_const<T>::value &&
                                       !std::is_pointer<Container>::value,
                                   Container>>
  Span(const Container &container)
      : data_(container.data()), size_(container.size()) {}

  template <typename Container,
            typename = enable_if_t<!std::is_const<T>::value &&
                                       !std::is_pointer<Container>::value,
                                   Container>>
  explicit Span(Container &container)
      : data_(container.data()), size_(container.size()) {}

  T *data() const { return data_; }
  size_t size() const { return size_; }
  void resize(size_t n) { size_ = n; }

  T *begin() const { return data_; }
  T *end() const { return data_ + size_; };

  T &operator[](size_t i) const { return data_[i]; }
  T &at(size_t i) const { return data_[i]; }

 private:
  T *data_;
  size_t size_;
};

template <typename T>
Span<T> MakeSpan(T *ptr, size_t size) {
  return Span<T>(ptr, size);
}

template <typename C>
auto MakeSpan(C &c) -> decltype(MakeSpan(c.data(), c.size())) {
  return MakeSpan(c.data(), c.size());
}

template <typename T>
Span<const T> MakeConstSpan(T *ptr, size_t size) {
  return Span<const T>(ptr, size);
}

template <typename C>
auto MakeConstSpan(const C &c) -> decltype(MakeConstSpan(c.data(), c.size())) {
  return MakeConstSpan(c.data(), c.size());
}

}  // namespace bssl

}  // extern C++
#endif  // defined __cplusplus

#endif /* OPENSSL_HEADER_SPAN_H */
