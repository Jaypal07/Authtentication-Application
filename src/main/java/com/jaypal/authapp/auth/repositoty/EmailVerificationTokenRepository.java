package com.jaypal.authapp.auth.repositoty;

import com.jaypal.authapp.user.model.User;
import com.jaypal.authapp.user.model.VerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface EmailVerificationTokenRepository extends JpaRepository<VerificationToken, Long> {
    Optional<VerificationToken> findByToken(String token);
    void deleteByUser(User user);
}
