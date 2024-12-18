package org.laalka.client.controllers;

import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;

@RestController
public class ClientController {

    @Value("${resource.server.url:http://localhost:8081")
    private String resourceServerUrl;

    private final OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager;
    private final RestTemplate restTemplate;

    public ClientController(OAuth2AuthorizedClientManager oAuth2AuthorizedClientManager) {
        this.oAuth2AuthorizedClientManager = oAuth2AuthorizedClientManager;
        this.restTemplate = new RestTemplate();
    }
    @GetMapping("/secured")
    public String securedEndpoint(OAuth2AuthenticationToken authentication) {
        return "You are authenticated as: " + authentication.getPrincipal().getName();
    }

    @GetMapping("/call")
    public String callResourceServer(@RegisteredOAuth2AuthorizedClient("my-client") OAuth2AuthorizedClient authorizedClient) {
        String token = authorizedClient.getAccessToken().getTokenValue();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);

        RequestEntity<Void> request = new RequestEntity<>(headers, HttpMethod.GET,
                java.net.URI.create(resourceServerUrl + "/private/data"));

        ResponseEntity<String> response = restTemplate.exchange(request, String.class);
        return response.getBody();
    }
}
