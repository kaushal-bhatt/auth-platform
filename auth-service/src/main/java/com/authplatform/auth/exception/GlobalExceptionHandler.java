package com.authplatform.auth.exception;

import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(CustomException.class)
    public ResponseEntity<ErrorResponse> handleCustomException(CustomException e) {
        return ResponseEntity.status(e.getStatus()).body(new ErrorResponse(e.getStatus(), e.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(MethodArgumentNotValidException e) {
        String message = e.getBindingResult().getFieldErrors().stream()
            .findFirst()
            .map(FieldError::getDefaultMessage)
            .orElse("validation failed");
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorResponse(400, message));
    }

    /**
     * A body Jackson cannot parse is a client error, not a server error. Without this handler it
     * falls through to {@link #handleUnexpectedException} and returns 500 with a full stack trace
     * in the logs.
     * <p>
     * The parse error is deliberately NOT echoed: Jackson's message quotes the offending region
     * of the request body, which for {@code /auth/login} or {@code /auth/register} can be the
     * caller's password or email. Log only the exception type for the same reason.
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadableMessage(HttpMessageNotReadableException e) {
        log.warn("rejected a request with an unreadable body: exceptionType={}", e.getClass().getName());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .body(new ErrorResponse(400, "malformed request body"));
    }

    /**
     * A request for a path that does not exist is a client error, not a server error.
     * <p>
     * Without this handler it fell through to {@link #handleUnexpectedException}, which returned
     * {@code 500} and logged a full stack trace at ERROR for something as ordinary as a browser
     * auto-requesting {@code /favicon.ico}. Two things were wrong with that: the status misreported
     * a missing resource as a server fault, and - because every route here is reachable
     * unauthenticated - any caller could flood the logs with ERROR-level stack traces just by
     * requesting nonexistent paths in a loop. That is the same unbounded ERROR-log flooding vector
     * the passkey ceremonies were already hardened against.
     * <p>
     * The requested path is deliberately not echoed back in the response body, and is logged only
     * at DEBUG: it is caller-controlled text, so reflecting it would make this endpoint a trivial
     * reflection point and logging it at a routine level would restore the flooding vector in a
     * quieter form.
     */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<ErrorResponse> handleNoResourceFound(NoResourceFoundException e) {
        log.debug("no handler for requested path: exceptionType={}", e.getClass().getName());
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
            .body(new ErrorResponse(404, "not found"));
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorResponse> handleDataIntegrityViolationException(DataIntegrityViolationException e) {
        // Do NOT log the exception object or its message here: the postgres detail message
        // embeds the offending email address and the constraint/sql text, and this project
        // has a policy against writing personal data such as email addresses into logs. Log
        // only enough (class names) to diagnose which constraint family failed.
        Throwable mostSpecificCause = e.getMostSpecificCause();
        log.warn("data integrity violation while processing request: exceptionType={}, causeType={}",
            e.getClass().getName(), mostSpecificCause.getClass().getName());
        return ResponseEntity.status(HttpStatus.CONFLICT)
            .body(new ErrorResponse(409, "the request conflicts with existing data"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleUnexpectedException(Exception e) {
        log.error("unhandled exception while processing request", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
            .body(new ErrorResponse(500, "internal server error"));
    }
}
