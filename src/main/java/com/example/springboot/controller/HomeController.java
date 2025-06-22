package com.example.springboot.controller;

import my.util.EncDecModule;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
    @GetMapping("/")
    public String home(Model model) {
        EncDecModule enc;
        model.addAttribute("message", "Hello, Thymeleaf!");
        return "index";
    }
}
