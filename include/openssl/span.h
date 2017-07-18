#ifndef OPENSSL_HEADER_SPAN_H
#define OPENSSL_HEADER_SPAN_H

#if defined(__cplusplus)

extern "C++" {

namespace bssl {

template <typename T>
class Span;

namespace internal {
template <typename T>
class SpanBase {
  /* Put comparison operator implementations into a base class with const T, so
   * they can be used with any type that implicitly converts into a Span. */
  static_assert(std::is_const<T>::value,
                "Span<T> must be derived from SpanBase<const T>");

  friend bool operator==(Span<T> lhs, Span<T> rhs) {
    return std::equal(lhs.begin(), lhs.end(), rhs.begin());
  }

  friend bool operator!=(Span<T> lhs, Span<T> rhs) { return !(lhs == rhs); }
};
}  // namespace internal

/* A Span<T> is a non-owning reference to a contiguous array of objects of type
 * |T|. Conceptually, a Span is a simple a pointer to |T| and a count of
 * elements accessible via that pointer. The elements referenced by the Span can
 * be mutated if |T| is mutable.
 *
 * A Span can be constructed from container types implementing |data()| and
 * |size()| methods. If |T| is constant, construction from a container type is
 * implicit. This allows writing methods that accept data from some unspecified
 * container type:
 *
 * // Foo views data referenced by v.
 * void Foo(bssl::Span<const uint8_t> v) { ... }
 *
 * std::vector<uint8_t> vec;
 * Foo(vec);
 *
 * For mutable Spans, conversion is explicit:
 *
 * // FooMutate mutates data referenced by v.
 * void FooMutate(bssl::Span<uint8_t> v) { ... }
 *
 * FooMutate(bssl::Span<uint8_t>(vec));
 *
 * You can also use the |MakeSpan| and |MakeConstSpan| factory methods to
 * construct Spans in order to deduct the type of the Span automatically.
 *
 * FooMutate(bssl::MakeSpan(vec));
 *
 * Note that Spans have value type sematics. They are cheap to construct and
 * copy, and should be passed by value whenever a method would otherwise accept
 * a reference or pointer to a container or array. */
template <typename T>
class Span : private internal::SpanBase<const T> {
 public:
  constexpr Span() : Span(nullptr, 0) {}
  constexpr Span(T *ptr, size_t len) : data_(ptr), size_(len) {}
  template <size_t N>
  constexpr Span(T (&array)[N]) : Span(array, N) {}

  template <typename Container,
            typename = typename std::enable_if<
                std::is_const<T>::value && !std::is_pointer<Container>::value,
                Container>::type>
  Span(const Container &container)
      : data_(container.data()), size_(container.size()) {}

  template <typename Container,
            typename = typename std::enable_if<
                !std::is_const<T>::value && !std::is_pointer<Container>::value,
                Container>>
  explicit Span(Container &container)
      : data_(container.data()), size_(container.size()) {}

  T *data() const { return data_; }
  size_t size() const { return size_; }

  T *begin() const { return data_; }
  T *end() const { return data_ + size_; };

  T &operator[](size_t i) const { return data_[i]; }
  T &at(size_t i) const { return data_[i]; }

  bool operator==(Span<T> x) {
    return std::equal(begin(), end(), x.begin());
  }

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
