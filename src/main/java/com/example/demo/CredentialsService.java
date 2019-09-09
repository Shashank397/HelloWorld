package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CredentialsService implements UserDetailsService{

	@Autowired
	private CredentialsRepo repo;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		System.out.println("+++++++++++++++++in the loadUser method++++++++++++++++"+username);
		Credentials cred = repo.findByUsername(username);
		System.out.println("user found++++++++"+cred.getUsername()+"+++++"+cred.getPassword());
		if(cred==null)
			throw new UsernameNotFoundException("user not found");
		return new CredentialsPrinciples(cred);
	}
	
	public void saveCred(Credentials entity)
	{
		repo.save(entity);
	}
	
	
}
