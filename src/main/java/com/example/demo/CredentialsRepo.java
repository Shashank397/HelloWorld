package com.example.demo;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialsRepo extends CrudRepository<Credentials, String> {
	
	Credentials findByUsername(String username);

}
