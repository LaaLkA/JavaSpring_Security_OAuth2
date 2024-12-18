package org.laalka.authorizationserver.services;

import lombok.AllArgsConstructor;
import org.laalka.authorizationserver.entities.Role;
import org.laalka.authorizationserver.entities.User;
import org.laalka.authorizationserver.repositories.RoleRepository;
import org.laalka.authorizationserver.repositories.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public User regisrterUser(String userName, String rawPassword, String roleName) {
        User user = new User();
        user.setUsername(userName);
        user.setPassword(passwordEncoder.encode(rawPassword));
        Role role = roleRepository.findByName(roleName);
        if (role == null) {
            role = new Role();
            role.setName(roleName);
            roleRepository.save(role);
        }

        user.getRoles().add(role);
        return userRepository.save(user);
    }
}
