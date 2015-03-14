package verification;

public class UserBean {

	private String cname;
	private String bname;
	private String city;
	private String state;
	private String country;
	private String organization;
	private String email;
	private String domainRequest;
	
	public boolean valid;
	
	public String getBName() {
		return bname;
	}

	public void setBName(String newBname) {
		bname = newBname;
	}

	public String getCname() {
		return cname;
	}

	public void setCName(String newCname) {
		cname = newCname;
	}

	public String getCity() {
		return city;
	}

	public void setCity(String newCity) {
		city = newCity;
	}

	public String getState() {
		return state;
	}

	public void setState(String newState) {
		city = newState;
	}

	public String getCountry() {
		return country;
	}

	public void setCountry(String newCountry) {
		country = newCountry;
	}

	public String getOrganization() {
		return organization;
	}

	public void setOrganization(String newOrganization) {
		organization = newOrganization;
	}

	
	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}
	
	public String getdomainRequest() {
		return city;
	}

	public void setdomainRequest(String newdomainRequest) {
		city = newdomainRequest;
	}


	public boolean isValid() {
		return valid;
	}

	public void setValid(boolean newValid) {
		valid = newValid;
	}
	
	
}