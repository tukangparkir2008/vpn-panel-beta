// Middleware for handling errors

// Custom Error Classes
class AppError extends Error {
    constructor(message, statusCode) {
        super(message);
        this.statusCode = statusCode;
        this.isOperational = true;
        Error.captureStackTrace(this, this.constructor);
    }
}

class NotFoundError extends AppError {
    constructor(message = 'Resource not found') {
        super(message, 404);
    }
}

// Async Handler
const asyncHandler = fn => {
    return (req, res, next) => {
        Promise.resolve(fn(req, res, next)).catch(next);
    };
};

// Global Error Handler
const globalErrorHandler = (err, req, res, next) => {
    const statusCode = err.isOperational ? err.statusCode : 500;
    const message = err.isOperational ? err.message : 'Something went wrong!';
    res.status(statusCode).json({ message });
};

// Not Found Handler
const notFoundHandler = (req, res, next) => {
    next(new NotFoundError());
};

module.exports = {
    AppError,
    NotFoundError,
    asyncHandler,
    globalErrorHandler,
    notFoundHandler,
};