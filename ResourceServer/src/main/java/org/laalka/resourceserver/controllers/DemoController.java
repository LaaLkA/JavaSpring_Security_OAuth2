package org.laalka.resourceserver.controllers;

import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class DemoController {

    @GetMapping("/public/hello")
    public String publicHello() {
        return "Hello World";
    }

    @GetMapping("/private/data")
    public String privateData() {
        return "Private Data";
    }
}
