package com.tcs.kogr.webservice.restwebservice.model;

import java.util.Date;

public class User {
	
	private String name;
	private String id;
	
	private String address;
	private Date dob;
	
	@Override
	public String toString() {
		return "User [name=" + name + ", id=" + id + ", address=" + address + ", dob=" + dob + "]";
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	
	public User(String name) {
		super();
		this.name = name;
	}
	 
	public User(String name, String address) {
		super();
		this.name = name;
		this.address = address;
	}
	public String getAddress() {
		return address;
	}
	public void setAddress(String address) {
		this.address = address;
	}
	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public Date getDob() {
		return dob;
	}
	public void setDob(Date dob) {
		this.dob = dob;
	}
	

}
