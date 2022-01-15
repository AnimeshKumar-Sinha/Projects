package com.tcs.kogr.webservice.restwebservice.controller;

import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import com.tcs.kogr.webservice.restwebservice.model.User;

@RestController
public class TestController {
	
	
	@RequestMapping(method=RequestMethod.GET,path="/healthcheckup")
	public String healthCheckMethod() {
		return "I AM UP";
	}
	
	@RequestMapping(method=RequestMethod.GET,path="/myInfo")
	public User healthPersonalInfo() {
		return new User("Animesh", "21074, Lavina ct, Cupertino, USA,");
	}
    
	
	@RequestMapping(method=RequestMethod.GET,path="/pathvariable/{name}")
	public User healthPathVariable(@PathVariable String name) {
		return new User(String.format("hello %s", name));
	}

}
