package org.laalka.authorizationserver.services;


import lombok.AllArgsConstructor;
import org.laalka.authorizationserver.Repository.UserRepository;
import org.laalka.authorizationserver.models.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException(username));
        UserBuilder builder = org.springframework.security.core.userdetails.User.withUsername(username)
    }
}
