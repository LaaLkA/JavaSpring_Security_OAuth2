package org.laalka.client.controllers;

import org.springframework.http.*;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class ClientController {

    @GetMapping("/public/hello")
    public String publicHello() {
        return "Hello from public endpoint!";
    }

    @GetMapping("/secured")
    public String secured(OAuth2AuthenticationToken authentication) {
        return "You are authenticated as: " + authentication.getPrincipal().getName();
    }

    @GetMapping("/call-resource")
    public String callResource(@RegisteredOAuth2AuthorizedClient("my-client") OAuth2AuthorizedClient client) {
        // Используем токен для вызова Resource Server
        String token = client.getAccessToken().getTokenValue();
        RestTemplate rest = new RestTemplate();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        ResponseEntity<String> response = rest.exchange(
                "http://localhost:8081/private/data",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class
        );
        return response.getBody();
    }
}