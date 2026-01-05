package com.jaypal.authapp.audit.model;

public enum AuthAuditEvent {

    // ---------- AUTH ----------
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    LOGOUT,

    // ---------- REGISTRATION ----------
    REGISTER,
    EMAIL_VERIFY,
    EMAIL_VERIFICATION_RESEND,

    // ---------- OAUTH ----------
    OAUTH_LOGIN_SUCCESS,
    OAUTH_LOGIN_FAILURE,

    // ---------- TOKEN ----------
    TOKEN_REFRESH,
    TOKEN_ROTATION,
    TOKEN_REVOKED,

    // ---------- PASSWORD ----------
    PASSWORD_CHANGE,          // user is logged in
    FORGOT_PASSWORD_REQUEST,  // email sent
    PASSWORD_RESET_SUCCESS,   // token based reset
    PASSWORD_RESET_FAILURE,

    // ---------- ACCOUNT ----------
    ACCOUNT_DISABLED
}

