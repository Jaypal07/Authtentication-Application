package com.jaypal.authapp.auth.exception;

import com.jaypal.authapp.shared.exception.DomainException;

public class EmailDeliveryException extends DomainException {
    public EmailDeliveryException(String message) {
        super(message);
    }
}
