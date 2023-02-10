package com.cybersoft.demojwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication( exclude = {SecurityAutoConfiguration.class} )
public class DemojwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(DemojwtApplication.class, args);
	}

}
