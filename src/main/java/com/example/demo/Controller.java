package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(origins="http://localhost:3000")
public class Controller {
	
	@Autowired
	private CredentialsService service;
	
	BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
	
	
	private Credentials cred = new Credentials();

	@GetMapping("/start")
	public String hello()
	{
		System.out.println("start method is called");
		return "Hello world";
	}
	
	@PostMapping("/login")
	public String login()
	{
		return "Login page";
	}
	
	@RequestMapping("/logout-success")
	public String logout()
	{
		return "logout";
	}
	
	@GetMapping("/saveCred/{username}/{password}")
	public String saveCredentials(@PathVariable("username") String username, @PathVariable("password") String password)
	{
		cred.setUsername(username);
		String pass = encoder.encode(password);
		cred.setPassword(pass);
		service.saveCred(cred);
		return "saved";
	}
	
}
