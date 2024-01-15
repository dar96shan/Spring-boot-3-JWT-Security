package com.security.simple.controlller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @GetMapping("/account")
    public String account(){
        return "Hi Welcome";
    }

    @GetMapping("/balance")
    public String balance(){
        return "Your Balance = "+1000;
    }

    @GetMapping("/update")
    public String update(){
        return "We have new update for you";
    }

    @GetMapping("/main")
    public String mainPage(){
        return "This is main Page";
    }
}
