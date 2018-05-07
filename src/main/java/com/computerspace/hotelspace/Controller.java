package com.computerspace.hotelspace;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;



@org.springframework.stereotype.Controller

public class Controller {

	
	@GetMapping("/marketing")
	public String marketing() {
		
		return "logout";

	}
	
	@GetMapping("/403")
	public String error_auth() {
	
		return "error_auth";

	
	}
	@GetMapping("/desarrollo")
	public String desarrollo() {
		
		return "logout";

	}
	@GetMapping("/admin")
	public String admin() {
		
		return "logout";

	}
	@GetMapping("/")
	public String inicio() {
		return "helloWorld";
	}
	@GetMapping("/logout")
	public String logoutPage (HttpServletRequest request, HttpServletResponse response) {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if(auth != null) {
			new SecurityContextLogoutHandler().logout(request,response,auth);
	
		}
		return "redirect:/";
		
		
	}
	
	
}



