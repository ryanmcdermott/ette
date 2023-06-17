
#ifndef __STATUS_H__
#define __STATUS_H__

#include <optional>
#include <stdexcept>
#include <string>
#include <variant>

namespace ette {
enum class StatusCode {
    kOk,
    kHeaderNoMagicNumber,
    kHeaderInvalidAlgorithm,
    kHeaderInvalidPlaintextSize,
    kHeaderInvalidIvSize,
    kInvalidKeySize,
    kInvalidKey,
    kInvalidDataSize,
    kInvalidIvSize,
    kUnknownError,
};

class Error {
   public:
    Error(StatusCode code, const std::string& message)
        : code_(code), message_(message) {}

    StatusCode code() const { return code_; }
    const std::string& message() const { return message_; }

   private:
    StatusCode code_;
    std::string message_;
};

template <typename T>
class Status {
   public:
    Status(T value) : status_(std::move(value)) {}

    Status(StatusCode code, const std::string& message)
        : status_(Error(code, message)) {}

    bool ok() const { return std::holds_alternative<T>(status_); }

    const T& value() const {
        if (!ok()) {
            throw std::runtime_error("Bad access to value");
        }

        return std::get<T>(status_);
    }

    const Error& error() const {
        if (ok()) {
            throw std::runtime_error("Bad access to error");
        }

        return std::get<Error>(status_);
    }

    const T& operator*() const { return value(); }

   private:
    std::variant<T, Error> status_;
};

template <>
class Status<void> {
   public:
    Status() {}

    Status(StatusCode code, const std::string& message)
        : status_(Error(code, message)) {}

    bool ok() const {
        return status_.has_value() && status_.value().code() == StatusCode::kOk;
    }

    const Error& error() const {
        if (ok()) {
            throw std::runtime_error("Bad access to error");
        }
        return status_.value();
    }

   private:
    std::optional<Error> status_;
};
}  // namespace ette
#endif  // __STATUS_H__