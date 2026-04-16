#ifndef DPI_COMPAT_OPTIONAL_H
#define DPI_COMPAT_OPTIONAL_H

#if defined(__has_include)
#  if __has_include(<optional>)
#    include <optional>
#  elif __has_include(<experimental/optional>)
#    include <experimental/optional>
namespace std {
using experimental::make_optional;
using experimental::nullopt;
using experimental::nullopt_t;
using experimental::optional;
}
#  else
#    error "No optional implementation found. Please use a newer compiler."
#  endif
#else
#  include <optional>
#endif

#endif // DPI_COMPAT_OPTIONAL_H