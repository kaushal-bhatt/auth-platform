package com.authplatform.auth.exception;

import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.mock.http.MockHttpInputMessage;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handlesCustomExceptionWithItsOwnStatus() {
        CustomException exception = new CustomException(409, "email is already registered");

        ResponseEntity<ErrorResponse> response = handler.handleCustomException(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isEqualTo(new ErrorResponse(409, "email is already registered"));
    }

    @Test
    void handlesValidationExceptionWithFieldMessage() {
        MethodArgumentNotValidException exception = mock(MethodArgumentNotValidException.class);
        BindingResult bindingResult = mock(BindingResult.class);
        FieldError fieldError = new FieldError("registerRequest", "password", "password must be between 8 and 128 characters");
        when(exception.getBindingResult()).thenReturn(bindingResult);
        when(bindingResult.getFieldErrors()).thenReturn(java.util.List.of(fieldError));

        ResponseEntity<ErrorResponse> response = handler.handleValidationException(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isEqualTo(
            new ErrorResponse(400, "password must be between 8 and 128 characters"));
    }

    @Test
    void handlesDataIntegrityViolationWithGenericMessageAndNoLeak() {
        String rawSqlDetail = "duplicate key value violates unique constraint \"app_user_email_key\" "
            + "Detail: Key (email)=(dup-user@example.com) already exists.";
        DataIntegrityViolationException exception = new DataIntegrityViolationException(rawSqlDetail);

        ResponseEntity<ErrorResponse> response = handler.handleDataIntegrityViolationException(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isEqualTo(new ErrorResponse(409, "the request conflicts with existing data"));
        assertThat(response.getBody().message()).doesNotContain("constraint");
        assertThat(response.getBody().message()).doesNotContain("app_user_email_key");
        assertThat(response.getBody().message()).doesNotContain("dup-user@example.com");
        assertThat(response.getBody().message()).doesNotContain(rawSqlDetail);
    }

    /**
     * A body Jackson cannot parse is a client error. Without a dedicated handler it fell through to
     * {@link GlobalExceptionHandler#handleUnexpectedException} and returned 500. The parse error
     * must not be echoed: Jackson's message quotes the offending region of the request body, which
     * for {@code /auth/login} is the caller's email and password.
     */
    @Test
    void handlesUnreadableMessageAsBadRequestWithoutEchoingTheParseError() {
        String rawBody = "{\"email\":\"leaky@example.com\",\"password\":\"super-secret-password\"";
        HttpMessageNotReadableException exception = new HttpMessageNotReadableException(
            "JSON parse error: Unexpected end-of-input while parsing " + rawBody,
            new MockHttpInputMessage(rawBody.getBytes(StandardCharsets.UTF_8)));

        ResponseEntity<ErrorResponse> response = handler.handleUnreadableMessage(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isEqualTo(new ErrorResponse(400, "malformed request body"));
        assertThat(response.getBody().message()).doesNotContain("super-secret-password");
        assertThat(response.getBody().message()).doesNotContain("leaky@example.com");
        assertThat(response.getBody().message()).doesNotContain(rawBody);
        assertThat(response.getBody().message()).doesNotContain("JSON parse error");
    }

    /**
     * A request for a nonexistent path is a client error. Without a dedicated handler it fell
     * through to {@link GlobalExceptionHandler#handleUnexpectedException}: {@code 500} plus a full
     * stack trace at ERROR for something as routine as a browser auto-requesting
     * {@code /favicon.ico} - and, since every route is reachable unauthenticated, an unbounded
     * ERROR-log flooding vector. The caller-supplied path must not be echoed back.
     */
    @Test
    void handlesMissingResourceAsNotFoundWithoutEchoingThePath() {
        NoResourceFoundException exception =
            new NoResourceFoundException(HttpMethod.GET, "/favicon.ico");

        ResponseEntity<ErrorResponse> response = handler.handleNoResourceFound(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).isEqualTo(new ErrorResponse(404, "not found"));
        assertThat(response.getBody().message()).doesNotContain("favicon.ico");
    }

    @Test
    void handlesUnexpectedExceptionWithFixedGenericMessage() {
        RuntimeException exception = new RuntimeException("some internal secret detail that must not leak");

        ResponseEntity<ErrorResponse> response = handler.handleUnexpectedException(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isEqualTo(new ErrorResponse(500, "internal server error"));
        assertThat(response.getBody().message()).doesNotContain("secret detail");
    }
}
