package com.authplatform.auth.repository;

import com.authplatform.auth.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.Set;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByEmail(String email);
    boolean existsByEmail(String email);

    /**
     * The user's granted roles, without loading the user.
     * <p>
     * Token issuance needs the roles and nothing else about the account, and it runs on every
     * login and every refresh. Fetching the entity to reach a collection it already owns would
     * pull the password hash and timestamps into memory on the hottest path in the service for
     * no reason.
     */
    @Query("select r from UserEntity u join u.roles r where u.id = :userId")
    Set<String> findRolesByUserId(@Param("userId") Long userId);
}
