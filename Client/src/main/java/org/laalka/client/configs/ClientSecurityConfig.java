package org.laalka.client.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ClientSecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/", "/public/**").permitAll()
                        .anyRequest().authenticated()
                )
                // Включаем OAuth2 Login - при запросе к защищённому URL без токена будет редирект на AS
                .oauth2Login(Customizer.withDefaults());

        return http.build();
    }
}
