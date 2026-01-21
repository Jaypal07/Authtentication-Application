package com.jaypal.authapp.common.aspect;

import com.jaypal.authapp.domain.audit.entity.AuditCategory;
import com.jaypal.authapp.domain.audit.entity.AuthAuditEvent;
import org.springframework.stereotype.Component;

/**
 * Dedicated component for category resolution.
 * Extracted from aspect for better testability and reusability.
 */
@Component
public class AuditCategoryResolver {

    public AuditCategory resolve(AuthAuditEvent event) {
        return switch (event) {
            case LOGIN, LOGOUT_SINGLE_SESSION, LOGOUT_ALL_SESSIONS, REGISTER,
                 EMAIL_VERIFICATION, EMAIL_VERIFICATION_RESEND, OAUTH_LOGIN,
                 TOKEN_ISSUED, TOKEN_REFRESH, TOKEN_REVOKED_SINGLE, TOKEN_REVOKED_ALL ->
                    AuditCategory.AUTHENTICATION;

            case TOKEN_INTROSPECTION, RATE_LIMIT_EXCEEDED,
                 SECURITY_POLICY_VIOLATION, SYSTEM_ERROR ->
                    AuditCategory.SYSTEM;

            case PASSWORD_CHANGE, PASSWORD_RESET_REQUESTED, PASSWORD_RESET,
                 ACCOUNT_VIEWED_SELF, ACCOUNT_UPDATED_SELF,
                 ACCOUNT_DISABLED_BY_ADMIN, ACCOUNT_DELETED_SELF,
                 ACCOUNT_LOCKED, ACCOUNT_UNLOCKED ->
                    AuditCategory.ACCOUNT;

            case ROLE_ASSIGNED, ROLE_REMOVED, PERMISSION_GRANTED,
                 PERMISSION_REVOKED, ACCESS_DENIED ->
                    AuditCategory.AUTHORIZATION;

            case ADMIN_USER_CREATED, ADMIN_USER_UPDATED, ADMIN_USER_DELETED,
                 ADMIN_USER_VIEWED, ADMIN_USER_LISTED,
                 ADMIN_ROLE_MODIFIED, ADMIN_PERMISSION_MODIFIED,
                 ADMIN_ACTION_GENERIC ->
                    AuditCategory.ADMIN;
        };
    }
}