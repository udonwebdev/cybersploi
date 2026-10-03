/**
 * Global error handler middleware
 */
const errorHandler = (err, req, res, next) => {
  console.error('[ERROR]', err);

  // Validation errors (Zod)
  if (err.name === 'ZodError') {
    const issues = err.issues.map(issue => ({
      field: issue.path.join('.'),
      message: issue.message
    }));
    
    return res.status(400).json({
      success: false,
      error: 'VALIDATION_ERROR',
      message: 'Request validation failed',
      details: issues
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      success: false,
      error: 'INVALID_TOKEN',
      message: 'Invalid token'
    });
  }

  // Prisma errors
  if (err.code && err.code.startsWith('P')) {
    if (err.code === 'P2002') {
      return res.status(409).json({
        success: false,
        error: 'DUPLICATE_ENTRY',
        message: `${err.meta?.target?.[0] || 'Field'} already exists`
      });
    }
    
    if (err.code === 'P2025') {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: 'Record not found'
      });
    }

    return res.status(400).json({
      success: false,
      error: 'DATABASE_ERROR',
      message: 'Database operation failed'
    });
  }

  // Application errors
  if (err.statusCode) {
    return res.status(err.statusCode).json({
      success: false,
      error: err.error || 'ERROR',
      message: err.message
    });
  }

  // Unknown error
  res.status(500).json({
    success: false,
    error: 'INTERNAL_SERVER_ERROR',
    message: process.env.NODE_ENV === 'production' 
      ? 'An unexpected error occurred' 
      : err.message
  });
};

module.exports = errorHandler;
