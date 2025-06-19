package com.rakkau.connectors;

import com.evolveum.polygon.rest.AbstractRestConfiguration;

public class SuccessFactorsConfiguration extends AbstractRestConfiguration {
	private String accountsQuery;
	private String emailTypeCode;
	private String phoneTypeCode;
	private String internalPhoneTypeCode;
	private String accountsFilter;
	private String url_token;
	private String assertion;
	private String company_id;
	private String client_id;
	private String authMethod;
	
	private String client_secret;
	private String url_sfsf_token;
	private String apiKey;
	
	//Estructura Organizacional
	private String businessUnitQuery;
	private String divisionsQuery;
	private String departmentsQuery;
	private String businessUnitFilter;
	private String divisionFilter;
	private String departmentFilter;

	public String getAuthMethod() {
		return authMethod;
	}
	public void setAuthMethod(String authMethod) {
		this.authMethod = authMethod;
	}
	public String getClient_id() {
		return client_id;
	}
	public void setClient_id(String client_id) {
		this.client_id = client_id;
	}

	public String getCompany_id() {
		return company_id;
	}
	public void setCompany_id(String company_id) {
		this.company_id = company_id;
	}

	public String getAssertion() {
		return assertion;
	}
	public void setAssertion(String assertion) {
		this.assertion = assertion;
	}

	public String getUrl_token() {
		return url_token;
	}
	public void setUrl_token(String url_token) {
		this.url_token= url_token;
	}

	public String getAccountsFilter() {
		return accountsFilter;
	}

	public void setAccountsFilter(String accountsFilter) {
		this.accountsFilter = accountsFilter;
	}

	public String getAccountsQuery() {
		return accountsQuery;
	}

	public void setAccountsQuery(String accountsQuery) {
		this.accountsQuery = accountsQuery;
	}

	public String getEmailTypeCode() {
		return emailTypeCode;
	}

	public void setEmailTypeCode(String emailTypeCode) {
		this.emailTypeCode = emailTypeCode;
	}

	public String getPhoneTypeCode() {
		return phoneTypeCode;
	}

	public void setPhoneTypeCode(String phoneTypeCode) {
		this.phoneTypeCode = phoneTypeCode;
	}

	public String getInternalPhoneTypeCode() {
		return internalPhoneTypeCode;
	}

	public void setInternalPhoneTypeCode(String internalPhoneTypeCode) {
		this.internalPhoneTypeCode = internalPhoneTypeCode;
	}
	
	public String getClient_secret() {
		return client_secret;
	}

	public void setClient_secret(String client_secret) {
		this.client_secret = client_secret;
	}

	public String getUrl_sfsf_token() {
		return url_sfsf_token;
	}

	public void setUrl_sfsf_token(String url_sfsf_token) {
		this.url_sfsf_token = url_sfsf_token;
	}
	
	public String getApiKey() {
		return apiKey;
	}
	
	public void setApiKey(String apiKey) {
		this.apiKey = apiKey;
	}
	
	//Estructura Organizacional
	public String getBusinessUnitQuery() {
		return businessUnitQuery;
	}

	public void setBusinessUnitQuery(String businessUnitQuery) {
		this.businessUnitQuery = businessUnitQuery;
	}
	
	public String getDivisionsQuery() {
		return divisionsQuery;
	}

	public void setDivisionsQuery(String divisionsQuery) {
		this.divisionsQuery = divisionsQuery;
	}
	
	public String getDepartmentsQuery() {
		return departmentsQuery;
	}

	public void setDepartmentsQuery(String departmentsQuery) {
		this.departmentsQuery = departmentsQuery;
	}
	
	public String getBusinessUnitFilter() {
		return businessUnitFilter;
	}

	public void setBusinessUnitFilter(String businessUnitFilter) {
		this.businessUnitFilter = businessUnitFilter;
	}
	
	public String getDivisionFilter() {
		return divisionFilter;
	}

	public void setDivisionFilter(String divisionFilter) {
		this.divisionFilter = divisionFilter;
	}
	
	public String getDepartmentFilter() {
		return departmentFilter;
	}

	public void setDepartmentFilter(String departmentFilter) {
		this.departmentFilter = departmentFilter;
	}
}