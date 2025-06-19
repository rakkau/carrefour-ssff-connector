package com.rakkau.connectors;

import com.evolveum.polygon.rest.AbstractRestConnector;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.codec.binary.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.message.BasicNameValuePair;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.*;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

import org.identityconnectors.common.security.GuardedString;
import java.nio.charset.StandardCharsets;

@ConnectorClass(displayNameKey = "connector.rakkau.rest.display", configurationClass = SuccessFactorsConfiguration.class)
public class SuccessFactorsConnector extends AbstractRestConnector<SuccessFactorsConfiguration> implements SchemaOp, TestOp, SearchOp<SuccessFactorsFilter>, UpdateDeltaOp {


	private static final Log logger = Log.getLog(SuccessFactorsConnector.class);
	private static final String ATTR_NEXT = "__next";
	private static final String ATTR_USER_ID = "userId";
	private static final String ATTR_PERSON_ID_EXTERNAL = "userId";
	private static final String ATTR_PERSON_NAV = "personNav";
	private static final String ATTR_EMPINFO = "empInfo";
	private static final String ATTR_DATE_OF_BIRTH = "dateOfBirth";
	private static final String ATTR_MANAGER = "manager";
	private static final String ATTR_MANAGER_ID = "managerId";
	private static final String ATTR_HIRE_DATE = "hireDate";
	private static final String ATTR_END_DATE = "endDate";
	private static final String ATTR_COMPANY = "company";


	private static final String ATTR_DESCRIPTION = "cost_center_description";
	private static final String ATTR_DEPARTMENT = "department";
	private static final String ATTR_JOB_CODE = "jobCode";
	private static final String ATTR_DIVISION = "division";
	private static final String ATTR_LOCATION = "location";
	private static final String ATTR_EVENT_REASON = "eventReason";
	private static final String ATTR_USERNAME = "username";
	private static final String ATTR_EMAIL = "email";
	private static final String ATTR_EMAIL_ADDRESS = "emailAddress";
	private static final String ATTR_PHONE_NAV = "phoneNav";
	private static final String ATTR_PHONE_NUMBER = "phoneNumber";
	private static final String ATTR_INTERNAL_PHONE_NUMBER = "internalPhoneNumber";
	private static final String ATTR_JOB_INFO_NAV = "jobInfoNav";
	private static final String ATTR_RESULTS = "results";
	private static final String ATTR_METADATA = "__metadata";
	private static final String ATTR_URI = "uri";
	private static final String ATTR_TYPE = "type";
	private static final String ATTR_IS_PRIMARY = "isPrimary";
	private static final String ATTR_NATIONAL_ID_NAV = "nationalIdNav";
	private static final String ATTR_NATIONAL_ID = "nationalId";
	private static final String ATTR_EMPLOYMENTNAV = "employmentNav";
	private static final String ATTR_CUIL = "cuil";
	private static final String ATTR_PERSONAL_INFO_NAV = "personalInfoNav";
	private static final String ATTR_FIRST_NAME = "firstName";
	private static final String ATTR_LAST_NAME = "lastName";
	private static final String ATTR_BUSINESS_UNIT = "businessUnit";
	private static final String ATTR_TITLE = "title";
	private static final String ATTR_CUSTOM_STRING_NAV = "customString17Nav";
	private static final String ATTR_CUSTOM_STRING_NAV_TITLE_DESC = "description";
	private static final String ATTR_DEPARTMENTNAV = "departmentNav";
	private static final String ATTR_DEPARTMENTNAV_DESC = "description";

	// Orgs Attributes
	private static final String ATTR_EXTERNAL_CODE = "externalCode";
	private static final String ATTR_PARENT = "parent";
	private static final String ATTR_NAME = "name";
	private static final String ATTR_STATUS = "status";

	// Custom Object Classes
	private static final String BUSINESSUNIT_OBJECT_CLASS = ObjectClassUtil.createSpecialName("BUSINESSUNIT");
	private static final String DIVISION_OBJECT_CLASS = ObjectClassUtil.createSpecialName("DIVISION");
	private static final String DEPARTMENT_OBJECT_CLASS = ObjectClassUtil.createSpecialName("DEPARTMENT");

	private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
	final Pattern NUMBER_MATCHER = Pattern.compile("(-?\\d+)");
	final Pattern DNI_MATCHER = Pattern.compile("\\d\\d-?(\\d+)-?\\d");
	private HttpUtils httpUtils;
	public static String accessToken;
	public static Long expiresAt;

	@Override
	public void init(Configuration configuration) {
		super.init(configuration);
		this.httpUtils = new HttpUtils(getHttpClient(), this.getConfiguration());
		this.sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
		logger.info("Success Factors rest connector initialized");
	}

	@Override
	public Schema schema() {
		logger.info("Processing Success Factors schemas");
		SchemaBuilder schemaBuilder = new SchemaBuilder(SuccessFactorsConnector.class);
		accountSchema(schemaBuilder);
		businessUnitSchema(schemaBuilder);
		divisionSchema(schemaBuilder);
		departmentSchema(schemaBuilder);
		System.out.println("Exiting schema builder");
		return schemaBuilder.build();
	}

	private void accountSchema(SchemaBuilder schemaBuilder) {
		ObjectClassInfoBuilder accountBuilder = new ObjectClassInfoBuilder();
		accountBuilder.setType(ObjectClass.ACCOUNT_NAME);
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_USER_ID).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_FIRST_NAME).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_LAST_NAME).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_DATE_OF_BIRTH).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_MANAGER).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_HIRE_DATE).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_END_DATE).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_COMPANY).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_DESCRIPTION).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_TITLE).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_JOB_CODE).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_DIVISION).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_LOCATION).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_EVENT_REASON).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_USERNAME).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_EMAIL_ADDRESS).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_PHONE_NUMBER).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_INTERNAL_PHONE_NUMBER).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_DEPARTMENT).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_NATIONAL_ID).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_CUIL).build());
		accountBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_BUSINESS_UNIT).build());

		schemaBuilder.defineObjectClass(accountBuilder.build());
	}
	
	private void businessUnitSchema(SchemaBuilder schemaBuilder) {
		System.out.println("DENTRO businessUnitSchema");
		ObjectClassInfoBuilder businessUnitBuilder = new ObjectClassInfoBuilder();
		businessUnitBuilder.setType(BUSINESSUNIT_OBJECT_CLASS);
		businessUnitBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_EXTERNAL_CODE).build());
		businessUnitBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_PARENT).build());
		businessUnitBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_NAME).build());
		businessUnitBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_STATUS).build());

		schemaBuilder.defineObjectClass(businessUnitBuilder.build());
	}
	
	private void divisionSchema(SchemaBuilder schemaBuilder) {
		System.out.println("DENTRO divisionSchema");
		ObjectClassInfoBuilder divisionBuilder = new ObjectClassInfoBuilder();
		divisionBuilder.setType(DIVISION_OBJECT_CLASS);
		divisionBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_EXTERNAL_CODE).build());
		divisionBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_PARENT).build());
		divisionBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_NAME).build());
		divisionBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_STATUS).build());
		schemaBuilder.defineObjectClass(divisionBuilder.build());
	}
	
	private void departmentSchema(SchemaBuilder schemaBuilder) {
		ObjectClassInfoBuilder departmentBuilder = new ObjectClassInfoBuilder();
		departmentBuilder.setType(DEPARTMENT_OBJECT_CLASS);
		departmentBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_EXTERNAL_CODE).build());
		departmentBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_PARENT).build());
		departmentBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_NAME).build());
		departmentBuilder.addAttributeInfo(new AttributeInfoBuilder(ATTR_STATUS).build());
		schemaBuilder.defineObjectClass(departmentBuilder.build());
	}

	@Override
	public FilterTranslator createFilterTranslator(ObjectClass objectClass, OperationOptions operationOptions) {
		return new SuccessFactorsFilterTranslator();
	}

	@Override
	public void executeQuery(ObjectClass objectClass, SuccessFactorsFilter query, ResultsHandler resultsHandler, OperationOptions options) {
		logger.info("ExecuteQuery on {0}, query: {1}, page size: {2}, page offset: {3}", objectClass, query, options.getPageSize(), options.getPagedResultsOffset());
		if (objectClass.is(ObjectClass.ACCOUNT_NAME)) {
			queryAccounts(query, resultsHandler, options);
		} else if (objectClass.is(BUSINESSUNIT_OBJECT_CLASS)) {
			System.out.println("DENTRO executeQuery BUSINESSUNIT_OBJECT_CLASS");
			queryBusinessUnits(query, resultsHandler, options);
		} else if (objectClass.is(DIVISION_OBJECT_CLASS)) {
			System.out.println("DENTRO executeQuery DIVISION_OBJECT_CLASS");
			queryDivisions(query, resultsHandler, options);
		} else if (objectClass.is(DEPARTMENT_OBJECT_CLASS)) {
			System.out.println("DENTRO executeQuery DEPARTMENT_OBJECT_CLASS");
			queryDepartments(query, resultsHandler, options);
		} else {
			throw new ConnectorException("ObjectClass " + objectClass.getObjectClassValue() + " unknown on executeQuery");
		}
	}

	protected JsonNode callRequestJson(HttpEntityEnclosingRequestBase request, JsonNode jo) {
		request.setHeader("Content-Type", "application/json");
		HttpEntity entity = new ByteArrayEntity(StringUtils.getBytesUtf8(jo.toString()));
		request.setEntity(entity);
		return callRequestAuth(request);
	}

	public JsonNode callRequestAuth(HttpRequestBase request){
		if (getConfiguration().getAuthMethod().equalsIgnoreCase("TOKEN")) {
			logger.info("Adding token authorization");
			String token = checkToken();
			request.setHeader("Authorization", "Bearer " + token);
		}
		return httpUtils.callRequest(request);
	}

	public String getToken() {
		System.out.println("Iniciando flujo para obtener token de SuccessFactors");

		// Paso 1: Obtener IAS Access Token
		String iasAccessToken = getIasAccessToken();

		System.out.println("Despues de paso 1. Valor de IASACCESTOKEN: " + iasAccessToken);
		// Paso 2: Intercambiar IAS token por SAML Assertion
		String samlAssertion = getSamlAssertionFromIas(iasAccessToken);

		System.out.println("Despues de paso 2. Valor de SAMLASSERTION: " + samlAssertion);
		// Paso 3: Usar assertion para obtener el token final de SuccessFactors
		String finalAccessToken = getSfsfAccessTokenFromAssertion(samlAssertion);

		System.out.println("Despues de paso 3. Valor de FINALACCESSTOKEN: " + finalAccessToken);
		this.accessToken = finalAccessToken;
		this.expiresAt = System.currentTimeMillis() + 3600 * 1000L;

		return accessToken;
	}
	
	private String getIasAccessToken() {
		System.out.println("Obteniendo token de SuccessFactors usando OAuth 2.0 password grant");
		HttpPost request = new HttpPost(this.getConfiguration().getUrl_token());

		GuardedString passwordGuarded = this.getConfiguration().getPassword();
		final String[] passwordHolder = new String[1];

		passwordGuarded.access(new GuardedString.Accessor() {
			@Override
			public void access(char[] chars) {
				passwordHolder[0] = new String(chars);
			}
		});

		String password = passwordHolder[0];

		List<NameValuePair> params = new ArrayList<>();		
		params.add(new BasicNameValuePair("grant_type", "password"));
		params.add(new BasicNameValuePair("username", this.getConfiguration().getUsername()));
		params.add(new BasicNameValuePair("password", password));
		params.add(new BasicNameValuePair("client_id", this.getConfiguration().getClient_id()));
		params.add(new BasicNameValuePair("client_secret", this.getConfiguration().getClient_secret())); // Si es necesario

		System.out.println("PARAMS FINALES: " + params);
		try {
			request.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}

		System.out.println("ANTES REQUEST SET HEADER");
		request.setHeader("Content-Type", "application/x-www-form-urlencoded");
		
		System.out.println("ANTES RESPONSE CALL REQUEST: "+request);
		JsonNode response = this.httpUtils.callRequest(request);

		System.out.println("ANTES DE RETORNAR ACCESS TOKEN: " + response.get("access_token").asText());
		return response.get("access_token").asText();
	}

	private String getSamlAssertionFromIas(String iasAccessToken) {
		System.out.println("Obteniendo SAML Assertion usando token exchange");
		HttpPost request = new HttpPost(this.getConfiguration().getUrl_token());

		List<NameValuePair> params = new ArrayList<>();
		params.add(new BasicNameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange"));
		params.add(new BasicNameValuePair("subject_token", iasAccessToken));
		params.add(new BasicNameValuePair("resource", "urn:sap:identity:application:provider:name:SFSAML"));
		params.add(new BasicNameValuePair("requested_token_type", "urn:ietf:params:oauth:token-type:saml2"));
		params.add(new BasicNameValuePair("subject_token_type", "urn:ietf:params:oauth:token-type:access_token"));

		try {
			request.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}

		// Headers
		request.setHeader("Content-Type", "application/x-www-form-urlencoded");

		// Autenticación con client_id y secret en Authorization: Basic
		String auth = this.getConfiguration().getClient_id() + ":" + this.getConfiguration().getClient_secret();
		String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));
		request.setHeader("Authorization", "Basic " + encodedAuth); // <- Este es el header correcto

		JsonNode response = this.httpUtils.callRequest(request);

		return response.get("access_token").asText();
	}

	private String getSfsfAccessTokenFromAssertion(String assertion) {
		System.out.println("Obteniendo token de SuccessFactors usando SAML assertion");

		HttpPost request = new HttpPost(this.getConfiguration().getUrl_sfsf_token());

		List<NameValuePair> params = new ArrayList<>();
		params.add(new BasicNameValuePair("client_id", this.getConfiguration().getApiKey()));  // <-- Este es el API Key
		params.add(new BasicNameValuePair("company_id", this.getConfiguration().getCompany_id()));
		params.add(new BasicNameValuePair("grant_type", "urn:ietf:params:oauth:grant-type:saml2-bearer"));
		params.add(new BasicNameValuePair("assertion", assertion));

		try {
			request.setEntity(new UrlEncodedFormEntity(params, "UTF-8"));
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e);
		}

		request.setHeader("Content-Type", "application/x-www-form-urlencoded");

		JsonNode response = this.httpUtils.callRequest(request);

		return response.get("access_token").asText();
	}


	public String checkToken() {
		if(this.isTokenExpired()) {
			logger.info("Access token expired. Expired at: {0})", expiresAt );
			return getToken();
		}
		System.out.println("Token NOT expired");
		return accessToken;
	}

	public boolean isTokenExpired() {
		return accessToken == null || expiresAt == null ||expiresAt < System.currentTimeMillis();
	}
	
	private void queryAccounts(SuccessFactorsFilter query, ResultsHandler handler, OperationOptions options){
		System.out.println("QUERY: "+query);
		String queryURL = this.getConfiguration().getServiceAddress();
		queryURL = queryURL + this.getConfiguration().getAccountsQuery();

		List<String> filters = new ArrayList<>();
		if (this.getConfiguration().getAccountsFilter() != null) {
			logger.info("Adding configured filter to query: {0}", this.getConfiguration().getAccountsFilter());
			filters.add(this.getConfiguration().getAccountsFilter());
		}

		List<String> conditions = new ArrayList<>();
		if (query != null) {
			if(StringUtil.isNotBlank(query.byUid)) {
				conditions.add(ATTR_PERSON_ID_EXTERNAL + " eq '" + query.byUid + "'");
			}
			if(StringUtil.isNotBlank(query.byName)) {
				conditions.add("tolower(" + ATTR_PERSON_ID_EXTERNAL + ") like '%" + query.byName.toLowerCase() + "%'");
			}
		}
		if(conditions.size() > 0) {
			logger.info("Setting accounts filter: {0}", conditions);
			queryURL = queryURL + "&$filter=" + HttpUtils.encodeURI(String.join(" and ", conditions));
		}
		if(filters.size() > 0 && conditions.size() > 0) {
			logger.info("Setting accounts filter: {0}", filters);
			queryURL = queryURL + "%20and%20" + HttpUtils.encodeURI(String.join(" and ", filters));
			logger.info("Query before characters replacement: {0}", queryURL);
			queryURL = queryURL.replaceAll("%26","&").replaceAll("%3D","=");
		} else if (filters.size() > 0){
			logger.info("Setting accounts filter: {0}", filters);
			queryURL = queryURL + "&$filter=" + HttpUtils.encodeURI(String.join(" and ", filters));
			logger.info("Query before characters replacement: {0}", queryURL);
			queryURL = queryURL.replaceAll("%26","&").replaceAll("%3D","=");
		}

		queryURL = queryURL + "&fromDate=" + getCurrentDate() + "&toDate=9999-12-31";
		System.out.println("queryURL: "+queryURL);

		// Iterate over a loop because results can be paginated
		while(StringUtil.isNotBlank(queryURL)) {
			logger.info("Querying accounts at {0}", queryURL);
			HttpGet request = new HttpGet(queryURL);
			JsonNode response = this.callRequestAuth(request);
			JsonNode root = response.get("d");
			JsonNode results = root.get("results");
			logger.info("Found {0} users", results.size());
			for(JsonNode user : results) {
				if (user.hasNonNull(ATTR_PERSON_ID_EXTERNAL)) {
					ConnectorObject connectorObject = convertUserToConnectorObject(user);
					handler.handle(connectorObject);
				}
			}
			logger.info("Query after querying, before next apply: {0}", queryURL);
			queryURL = root.hasNonNull(ATTR_NEXT) ? root.get(ATTR_NEXT).asText() : null;
			logger.info("Query after querying, with next apply: {0}", queryURL);
		System.out.println("queryURL: "+queryURL);
		}
	}

	private void queryBusinessUnits(SuccessFactorsFilter query, ResultsHandler handler, OperationOptions options) {

		// 0) Path base
		String queryURL = this.getConfiguration().getServiceAddress() + this.getConfiguration().getBusinessUnitQuery();

		// 1) Filtro fijo configurado en el recurso
		List<String> filters = new ArrayList<>();
		if (StringUtil.isNotBlank(this.getConfiguration().getBusinessUnitFilter())) {
			filters.add(this.getConfiguration().getBusinessUnitFilter());
			System.out.println("Adding configured BU filter: " + filters);
		}

		// 2) Condiciones dinámicas (uid / name)
		List<String> conditions = new ArrayList<>();
		if (query != null) {
			if (StringUtil.isNotBlank(query.byUid)) {
				conditions.add(ATTR_EXTERNAL_CODE + " eq '" + query.byUid + "'");
			}
			if (StringUtil.isNotBlank(query.byName)) {
				conditions.add("tolower(" + ATTR_NAME + ") like '%" + query.byName.toLowerCase() + "%'");
			}
		}

		// 3) Construir / concatenar $filter
		if (!conditions.isEmpty()) {
			String extra = HttpUtils.encodeURI(String.join(" and ", conditions));
			if (queryURL.contains("$filter=")) {
				queryURL += "%20and%20" + extra;
			} else {
				queryURL += "&$filter=" + extra;
			}
			System.out.println("Adding dynamic conditions: " + conditions);
		}

		if (!filters.isEmpty()) {
			String extra = HttpUtils.encodeURI(String.join(" and ", filters));
			if (queryURL.contains("$filter=")) {
				queryURL += "%20and%20" + extra;
			} else {
				queryURL += "&$filter=" + extra;
			}
			System.out.println("Final queryURL with static filters: " + queryURL);
		}

		// 4) (Opcional) ventana temporal — solo si aplica a BU
		// queryURL += "&fromDate=" + getCurrentDate() + "&toDate=9999-12-31";

		// 5) Bucle de paginación
		while (StringUtil.isNotBlank(queryURL)) {
			System.out.println("Querying businessUnits at: " + queryURL);
			JsonNode response = this.callRequestAuth(new HttpGet(queryURL));
			JsonNode root = response.get("d");
			JsonNode results  = root.get("results");

			System.out.println("Business Unit Query Response: " + response.toString());
			System.out.println("Found " + results.size() + " businessUnits");

			for (JsonNode bu : results) {
				ConnectorObject co = convertBusinessUnitToConnectorObject(bu);
				handler.handle(co);
			}

			queryURL = root.hasNonNull(ATTR_NEXT) ? root.get(ATTR_NEXT).asText() : null;
		}
	}

	
	private void queryDivisions(SuccessFactorsFilter query, ResultsHandler handler, OperationOptions options) {

		// 0) Path base
		String queryURL = this.getConfiguration().getServiceAddress() + this.getConfiguration().getDivisionsQuery();

		// 1) Filtro fijo configurado en el recurso
		List<String> filters = new ArrayList<>();
		if (StringUtil.isNotBlank(this.getConfiguration().getDivisionFilter())) {
			filters.add(this.getConfiguration().getDivisionFilter());
			System.out.println("Adding configured Division filter: " + filters);
		}

		// 2) Condiciones dinámicas (uid / name)
		List<String> conditions = new ArrayList<>();
		if (query != null) {
			if (StringUtil.isNotBlank(query.byUid)) {
				conditions.add(ATTR_EXTERNAL_CODE + " eq '" + query.byUid + "'");
			}
			if (StringUtil.isNotBlank(query.byName)) {
				conditions.add("tolower(" + ATTR_NAME + ") like '%" + query.byName.toLowerCase() + "%'");
			}
		}

		// 3) Construir / concatenar $filter
		if (!conditions.isEmpty()) {
			String extra = HttpUtils.encodeURI(String.join(" and ", conditions));
			if (queryURL.contains("$filter=")) {
				queryURL += "%20and%20" + extra;
			} else {
				queryURL += "&$filter=" + extra;
			}
			System.out.println("Adding dynamic Division conditions: " + conditions);
		}

		if (!filters.isEmpty()) {
			String extra = HttpUtils.encodeURI(String.join(" and ", filters));
			if (queryURL.contains("$filter=")) {
				queryURL += "%20and%20" + extra;
			} else {
				queryURL += "&$filter=" + extra;
			}
			System.out.println("Final Division queryURL with static filters: " + queryURL);
		}

		// 4) Bucle paginado
		while (StringUtil.isNotBlank(queryURL)) {
			System.out.println("Querying divisions at: " + queryURL);
			JsonNode response = this.callRequestAuth(new HttpGet(queryURL));
			JsonNode root = response.get("d");
			JsonNode results  = root.get("results");

			System.out.println("Division Query Response: " + response.toString());
			System.out.println("Found " + results.size() + " divisions");

			for (JsonNode div : results) {
				ConnectorObject co = convertDivisionToConnectorObject(div);
				handler.handle(co);
			}
			queryURL = root.hasNonNull(ATTR_NEXT) ? root.get(ATTR_NEXT).asText() : null;
		}
	}
	
	private void queryDepartments(SuccessFactorsFilter query, ResultsHandler handler, OperationOptions options) {

		// 0) Path base
		String queryURL = this.getConfiguration().getServiceAddress() + this.getConfiguration().getDepartmentsQuery();

		// 1) Filtro fijo configurado en el recurso
		List<String> filters = new ArrayList<>();
		if (StringUtil.isNotBlank(this.getConfiguration().getDepartmentFilter())) {
			filters.add(this.getConfiguration().getDepartmentFilter());
			System.out.println("Adding configured Department filter: " + filters);
		}

		// 2) Condiciones dinámicas (uid / name)
		List<String> conditions = new ArrayList<>();
		if (query != null) {
			if (StringUtil.isNotBlank(query.byUid)) {
				conditions.add(ATTR_EXTERNAL_CODE + " eq '" + query.byUid + "'");
			}
			if (StringUtil.isNotBlank(query.byName)) {
				conditions.add("tolower(" + ATTR_NAME + ") like '%" + query.byName.toLowerCase() + "%'");
			}
		}

		// 3) Construir / concatenar $filter
		if (!conditions.isEmpty()) {
			String extra = HttpUtils.encodeURI(String.join(" and ", conditions));
			if (queryURL.contains("$filter=")) {
				queryURL += "%20and%20" + extra;
			} else {
				queryURL += "&$filter=" + extra;
			}
			System.out.println("Adding dynamic Department conditions: " + conditions);
		}

		if (!filters.isEmpty()) {
			String extra = HttpUtils.encodeURI(String.join(" and ", filters));
			if (queryURL.contains("$filter=")) {
				queryURL += "%20and%20" + extra;
			} else {
				queryURL += "&$filter=" + extra;
			}
			System.out.println("Final Department queryURL with static filters: " + queryURL);
		}

		// 4) Bucle paginado
		while (StringUtil.isNotBlank(queryURL)) {
			System.out.println("Querying departments at: " + queryURL);
			JsonNode response = this.callRequestAuth(new HttpGet(queryURL));
			JsonNode root = response.get("d");
			JsonNode results  = root.get("results");

			System.out.println("Department Query Response: " + response.toString());
			System.out.println("Found " + results.size() + " departments");

			for (JsonNode dep : results) {
				ConnectorObject co = convertDepartmentToConnectorObject(dep);
				handler.handle(co);
			}
			queryURL = root.hasNonNull(ATTR_NEXT) ? root.get(ATTR_NEXT).asText() : null;
		}
	}
	
	private void getDateIfExists(JsonNode object, String attribute, ConnectorObjectBuilder builder) {
		if (object.hasNonNull(attribute)) {
			addAttr(builder, attribute, this.getDate(object.get(attribute)));
		}
	}
	private void getDateIfExists(JsonNode object, String attribute, ConnectorObjectBuilder builder, String builderAttr) {
		if (object.hasNonNull(attribute)) {
			addAttr(builder, builderAttr, this.getDate(object.get(attribute)));
		}
	}
	private void getIfExists(JsonNode object, String attribute, ConnectorObjectBuilder builder) {
		if (object.hasNonNull(attribute)) {
			JsonNode value = object.get(attribute);
			addAttr(builder, attribute, value.asText());
		}
	}
	private void getIfExists(JsonNode object, String objectAttr, ConnectorObjectBuilder builder, String builderAttr) {
		if (object.hasNonNull(objectAttr)) {
			JsonNode value = object.get(objectAttr);
			addAttr(builder, builderAttr, value.asText());
		}
	}
	/**
	 * Expects a date in the format "/Date(1589155200000)/" and returns it
	 * in the format YYYY-MM-DD.
	 * @param jsonDate String with the date in the format YYYY-MM-DD
	 */
	private String getDate(JsonNode date) {
		logger.ok("Converting date {0}", date);

		if (!date.isNull()) {
			logger.ok("Date {0}", date.asText());
			return this.sdf.format(new Date(Long.parseLong(extractNumbersFromString(date.asText()))));
		}

		return null;
	}

	/**
	 * Extracts contiguous digits from string:
	 * i.e.: CONTADURIA (123) --> 123
	 * @param input String containing text and numbers
	 * @return numbers matched
	 */
	private String extractNumbersFromString(String input) {
		Matcher m = NUMBER_MATCHER.matcher(input);
		if(m.find()) {
			logger.ok("extractNumbersFromString: Value found: {0}", m.group(1));
			return m.group(1);
		}
		return "";
	}
	/**
	 * Extracts user attributes from jobInfoNav object.
	 * @param builder
	 * @param jobInfoNav
	 * @return
	 */
	private void getAttrsFromJobInfoNav(ConnectorObjectBuilder builder, JsonNode jobInfoNav) {
		logger.info("Getting user attrs from json attribute jobInfoNav.");
		if (!jobInfoNav.hasNonNull(ATTR_RESULTS)) {return;}

		JsonNode results = jobInfoNav.get(ATTR_RESULTS);
		if (results.isArray() && results.size() > 0) {
			JsonNode firstResult = results.get(0);
			//getIfExists(firstResult, ATTR_MANAGER_ID, builder, ATTR_MANAGER);
			getIfExists(firstResult, ATTR_COMPANY, builder);
			getIfExists(firstResult, ATTR_EVENT_REASON, builder);
		}
	}
	/**
	 * Extracts user attributes from empInfo object.
	 * @param builder
	 * @param empInfo
	 * @return
	 */
	private void getAttrsFromEmpInfo(ConnectorObjectBuilder builder, JsonNode empInfo) {
		logger.info("Getting user attrs from json attribute empInfo");
		getDateIfExists(empInfo, ATTR_END_DATE, builder);

			if (empInfo.hasNonNull(ATTR_JOB_INFO_NAV)) {
				JsonNode jobInfoNav = empInfo.get(ATTR_JOB_INFO_NAV);
				getAttrsFromJobInfoNav(builder, jobInfoNav);
			}
			if (empInfo.hasNonNull(ATTR_PERSON_NAV)) {
				JsonNode personNav = empInfo.get(ATTR_PERSON_NAV);
				getAttrsFromPersonNav(builder, personNav);
			}
	}
	/**
	 * Extracts user attributes from personNav object.
	 * @param builder
	 * @param personNav
	 * @return
	 */
	private void getAttrsFromPersonNav(ConnectorObjectBuilder builder, JsonNode personNav) {
		System.out.println("Getting user attrs from json attribute personNav.");

		if (personNav.hasNonNull(ATTR_NATIONAL_ID_NAV)) {
		System.out.println("DENTRO PERSON NAV NATIONAL ID NAV");
			JsonNode nationalIdNav = personNav.get(ATTR_NATIONAL_ID_NAV);
			getAttrsFromNationalIdNav(builder, nationalIdNav);
		}
		if (personNav.hasNonNull(ATTR_PERSONAL_INFO_NAV)) {
			System.out.println("DENTRO PERSON NAV PERSONAL INFO NAV");
			JsonNode personalInfoNav = personNav.get(ATTR_PERSONAL_INFO_NAV);
			getAttrsFromPersonalInfoNav(builder, personalInfoNav);
		}
		if (personNav.hasNonNull(ATTR_PHONE_NAV)) {
			getAttrsFromPhoneNav(builder, personNav.get(ATTR_PHONE_NAV));
		}

	}
	private void getAttrsFromPhoneNav(ConnectorObjectBuilder builder, JsonNode phoneNav) {
		if (!phoneNav.hasNonNull(ATTR_RESULTS)) {return;}

		JsonNode results = phoneNav.get(ATTR_RESULTS);
		if (!results.isArray()) {return;}

		for (JsonNode obj : results) {
			if (obj.hasNonNull(ATTR_METADATA)) {
				JsonNode metadata = obj.get(ATTR_METADATA);
				if (metadata.hasNonNull(ATTR_URI)) {
					String uri = metadata.get(ATTR_URI).toString();
					if (uri.contains("phoneType='" + getConfiguration().getPhoneTypeCode() + "'")) {
						getIfExists(obj, ATTR_PHONE_NUMBER, builder, ATTR_PHONE_NUMBER);
					} else if (uri.contains("phoneType='" + getConfiguration().getInternalPhoneTypeCode() + "'")) {
						getIfExists(obj, ATTR_PHONE_NUMBER, builder, ATTR_INTERNAL_PHONE_NUMBER);
					}
				}
			}
		}
	}

	/**
	 * Converts a Json user received from SSFF into
	 * a valid user within midPoint.
	 * @param user
	 * @return
	 * @throws IOException
	 */
	private ConnectorObject convertUserToConnectorObject(JsonNode user)  {
		System.out.println("DENTRO CONVERTUSERTOCONNECTOROBJECT USER: "+user);
		logger.info("Converting json to connector object. User id: {0}", user.get(ATTR_PERSON_ID_EXTERNAL));
		ConnectorObjectBuilder builder = new ConnectorObjectBuilder();

		String uid = user.get(ATTR_PERSON_ID_EXTERNAL).asText();
		builder.setUid(new Uid(uid));
		builder.setName(uid);
		
		getIfExists(user, ATTR_PERSON_ID_EXTERNAL, builder, ATTR_USER_ID);
		getDateIfExists(user, ATTR_DATE_OF_BIRTH, builder);
		getDateIfExists(user, ATTR_HIRE_DATE, builder);
		getIfExists(user, ATTR_USERNAME, builder);
		getIfExists(user, ATTR_EMAIL, builder, ATTR_EMAIL_ADDRESS);
		//getIfExists(user, ATTR_TITLE, builder); //Lo debería tener en otro método
		//getIfExists(user, ATTR_FIRST_NAME, builder); //Lo tengo en otro metodo
		//getIfExists(user, ATTR_LAST_NAME, builder); //Lo tengo en otro metodo
		getIfExists(user, ATTR_MANAGER_ID, builder, ATTR_MANAGER);
		getIfExists(user, ATTR_BUSINESS_UNIT, builder);

		/*if (user.hasNonNull(ATTR_EMPINFO)) {
			JsonNode employmentNav = user.get(ATTR_EMPINFO);
			getAttrsFromEmpInfo(builder, employmentNav);
		}*/

		if(user.hasNonNull(ATTR_DIVISION)) {
			JsonNode division = user.get(ATTR_DIVISION);
			addAttr(builder, ATTR_DIVISION, getValueForAttribute(division.asText()));
		}

		if(user.hasNonNull(ATTR_JOB_CODE)) {
			JsonNode jobcode = user.get(ATTR_JOB_CODE);
			addAttr(builder, ATTR_JOB_CODE, getValueForAttribute(jobcode.asText()));
		}

		if(user.hasNonNull(ATTR_LOCATION)) {
		System.out.println("DENTRO USER HAS NO NULL LOCATION");
			JsonNode location = user.get(ATTR_LOCATION);
			addAttr(builder, ATTR_LOCATION, getValueForAttribute(location.asText()));
		}
		//DEPARTMENT LO TENGO QUE BUSCAR COMO departmentNav/Description
		/*if(user.hasNonNull(ATTR_DEPARTMENT)) {
			JsonNode department = user.get(ATTR_DEPARTMENT);
			addAttr(builder, ATTR_DEPARTMENT, extractLastString(department.asText()));
		}*/
		if (user.hasNonNull(ATTR_EMPLOYMENTNAV)) {
		System.out.println("DENTRO USER HAS NO NULL EMPLOYMENTNAV");
			JsonNode employmentNav = user.get(ATTR_EMPLOYMENTNAV);
			getAttrsFromEmploymentNav(builder, employmentNav);
		}
		if (user.hasNonNull(ATTR_CUSTOM_STRING_NAV)) {
		System.out.println("DENTRO USER HAS NO NULL CUSTOMSTRING17NAV");
			JsonNode custStringNav = user.get(ATTR_CUSTOM_STRING_NAV);
			getAttrsFromCustomStringNav(builder, custStringNav);
		}
		ConnectorObject connectorObject = builder.build();
		logger.ok("convertUserToConnectorObject, user: {0}, \n\tconnectorObject: {1}", user.get(ATTR_PERSON_ID_EXTERNAL), connectorObject);
		 return connectorObject;
	}
	
	private ConnectorObject convertBusinessUnitToConnectorObject(JsonNode businessUnit) {
		String externalCode = businessUnit.get(ATTR_EXTERNAL_CODE).asText();
		logger.info("Converting json to connector object. BusinessUnit id: {0}", externalCode);

		ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
		builder.setUid(new Uid(externalCode));
		builder.setName(externalCode);

		// Agregamos atributos seguros
		getIfExists(businessUnit, ATTR_NAME, builder);
		getIfExists(businessUnit, ATTR_EXTERNAL_CODE, builder);
		getIfExists(businessUnit, ATTR_STATUS, builder);

		ConnectorObject connectorObject = builder.build();
		logger.info("convertBusinessUnitToConnectorObject, id: {0}, \n\tconnectorObject: {1}", externalCode, connectorObject);
		return connectorObject;
	}

	private ConnectorObject convertDivisionToConnectorObject(JsonNode division) {

		String externalCode = division.get(ATTR_EXTERNAL_CODE).asText();
		logger.info("Converting json to connector object. Division id: {0}", externalCode);
		System.out.println("Converting json to connector object. Division id: " + externalCode);

		ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
		builder.setUid(new Uid(externalCode));
		builder.setName(externalCode);

		// Obtener parent directamente si existe
		if (division.hasNonNull("parent")) {
			String parentCode = division.get("parent").asText();
			System.out.println("OBTENIENDO PARENT: " + parentCode);
			builder.addAttribute(ATTR_PARENT, parentCode);
		}

		// Atributos adicionales
		getIfExists(division, ATTR_NAME, builder);
		getIfExists(division, ATTR_EXTERNAL_CODE, builder);
		getIfExists(division, ATTR_STATUS, builder);

		ConnectorObject connectorObject = builder.build();
		logger.ok("convertDivisionToConnectorObject, division: {0}, connectorObject: {1}", externalCode, connectorObject);
		return connectorObject;
	}

	private ConnectorObject convertDepartmentToConnectorObject(JsonNode department)  {
		String externalCode = department.get(ATTR_EXTERNAL_CODE).asText();
		logger.info("Converting json to connector object. Department id: {0}", externalCode);
		ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
		builder.setUid(new Uid(externalCode));
		builder.setName(externalCode);

		getIfExists(department, ATTR_NAME, builder);
		getIfExists(department, ATTR_EXTERNAL_CODE, builder);
		getIfExists(department, ATTR_PARENT, builder);
		getIfExists(department, ATTR_STATUS, builder);

		ConnectorObject connectorObject = builder.build();
		logger.ok("convertDepartmentToConnectorObject, user: {0}, \n\tconnectorObject: {1}", externalCode, connectorObject);
		return connectorObject;
	}

	@Override
	public void test() {
		logger.info("Testing connections to endpoints");
		try {
			logger.info("Testing service endpoint...");
			callRequestAuth(new HttpGet(getConfiguration().getServiceAddress()));
			logger.info("Testing service endpoint [OK]");
		} catch (Exception e) {
			throw new ConnectorIOException("Error when testing connection: " + e.getMessage(), e);
		}
	}

	@Override
	public Set<AttributeDelta> updateDelta(ObjectClass objectClass, Uid uid, Set<AttributeDelta> attributes, OperationOptions operationOptions) {
		logger.info("Updating entity with objectClass: {0}", objectClass);
		if(objectClass.is(ObjectClass.ACCOUNT_NAME)) {
			for(AttributeDelta attribute : attributes) {
				logger.info("Update - Attribute received {0}: {1}", attribute.getName(), attribute.toString());
				logger.info("Update - Values to replace: {0}", attribute.getValuesToReplace());
				logger.info("Update - Values to add: {0}", attribute.getValuesToAdd());
				logger.info("Update - Values to remove: {0}", attribute.getValuesToRemove());
				if (attribute.is(ATTR_USERNAME)) {
					this.updateUsername(uid, getFirstValue(attribute));
				} else if (attribute.is(ATTR_EMAIL_ADDRESS)) {
					this.updateEmail(uid, getFirstValue(attribute));
				} else if (attribute.is(ATTR_PHONE_NUMBER)) {
					this.updatePhone(uid, getFirstValue(attribute));
				} else if (attribute.is(ATTR_INTERNAL_PHONE_NUMBER)) {
					this.updateInternalPhone(uid, getFirstValue(attribute));
				}
			}
		}
		else {
			throw new ConnectorException("Update is not available for object class " + objectClass.getDisplayNameKey());
		}

		// The `updateDelta` only returns a hash with values if, for example, it performed a rename.
		// see: https://github.com/Evolveum/connector-gitlab-rest
		return new HashSet<>();
	}

	private void updateUsername(Uid uid, String username) {
		ObjectMapper mapper = new ObjectMapper();
		ObjectNode objectNode = mapper.createObjectNode();
		ObjectNode metadata = mapper.createObjectNode();
		metadata.put(ATTR_URI, String.format("User('%s')", uid.getUidValue()));
		objectNode.set(ATTR_METADATA, metadata);
		objectNode.put(ATTR_USERNAME, username);
		logger.info("Json created to update username: {0}", objectNode);

		this.callRequestJson(new HttpPost(this.getConfiguration().getServiceAddress() + "/upsert?processInactiveEmployees=true"), objectNode);
	}

	private void updateEmail(Uid uid, String email) {
		ObjectMapper mapper = new ObjectMapper();
		ObjectNode objectNode = mapper.createObjectNode();
		ObjectNode metadata = mapper.createObjectNode();
		metadata.put(ATTR_URI, String.format("PerEmail(emailType='%s',personIdExternal='%s')", getConfiguration().getEmailTypeCode(), uid.getUidValue()) );
		metadata.put(ATTR_TYPE,"SFOData.PerEmail");

		objectNode.set(ATTR_METADATA, metadata);
		objectNode.put(ATTR_EMAIL_ADDRESS, email);
		objectNode.put(ATTR_IS_PRIMARY, true);
		logger.info("Json created to update email: {0}", objectNode);

		this.callRequestJson(new HttpPost(this.getConfiguration().getServiceAddress() + "/upsert?processInactiveEmployees=true"), objectNode);
	}

	private void updatePhone(Uid uid, String phone) {
		ObjectMapper mapper = new ObjectMapper();
		ObjectNode objectNode = mapper.createObjectNode();
		ObjectNode metadata = mapper.createObjectNode();
		metadata.put(ATTR_URI, String.format("PerPhone(phoneType='%s',personIdExternal='%s')", getConfiguration().getPhoneTypeCode(), uid.getUidValue()));
		metadata.put(ATTR_TYPE,"SFOData.PerPhone");

		objectNode.set(ATTR_METADATA, metadata);
		objectNode.put(ATTR_PHONE_NUMBER, phone);
		objectNode.put(ATTR_IS_PRIMARY, true);
		logger.info("Json created to update phone: {0}", objectNode);

		this.callRequestJson(new HttpPost(this.getConfiguration().getServiceAddress() + "/upsert?processInactiveEmployees=true"), objectNode);
	}

	private void updateInternalPhone(Uid uid, String phone) {
		ObjectMapper mapper = new ObjectMapper();
		ObjectNode objectNode = mapper.createObjectNode();
		ObjectNode metadata = mapper.createObjectNode();
		metadata.put(ATTR_URI, String.format("PerPhone(phoneType='%s',personIdExternal='%s')", getConfiguration().getInternalPhoneTypeCode(), uid.getUidValue()));
		metadata.put(ATTR_TYPE,"SFOData.PerPhone");

		objectNode.set(ATTR_METADATA, metadata);
		objectNode.put(ATTR_PHONE_NUMBER, phone);
		objectNode.put(ATTR_IS_PRIMARY, false);
		logger.info("Json created to update phone: {0}", objectNode);

		this.callRequestJson(new HttpPost(this.getConfiguration().getServiceAddress() + "/upsert?processInactiveEmployees=true"), objectNode);
	}


	private String getFirstValue(AttributeDelta delta) {
		if(delta.getValuesToReplace().size() > 0) {
			return delta.getValuesToReplace().get(0).toString();
		}
		return null;
	}

	private String getValueForAttribute(String attribute) {
		//It retrieves the string from the last pair of parentheses.
		Pattern pattern = Pattern.compile("\\((.*?)\\)");
		Matcher matcher = pattern.matcher(attribute);
		String result = attribute;
		while (matcher.find()) {
			result = matcher.group(1);
		}
		return result;
	}

	private String extractLastString(String attribute) {
		Pattern pattern = Pattern.compile("\\((.*?)\\)");
		Matcher matcher = pattern.matcher(attribute);
		String result = attribute;
		while (matcher.find()) {
			result = result.replace("(" + matcher.group(1) + ")", "");
		}
		return result.trim();
	}

	public String getCurrentDate() {
		//Calculate the current date; it's used to pass it to the fromDate in the query.
		LocalDate currentDate = LocalDate.now();
		DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd");
		return currentDate.format(formatter);
	}

	/**
	 * Extracts DNI from nationalIdNav if exists. Otherwise its calculated from cuil.
	 * @param builder
	 * @param nationalIdNav
	 * @return
	 */
	private void getAttrsFromNationalIdNav(ConnectorObjectBuilder builder, JsonNode nationalIdNav) {
	System.out.println("Getting attrs from json attribute nationalIdNav.");
	if (!nationalIdNav.hasNonNull(ATTR_RESULTS)) {
		return;
	}

	JsonNode results = nationalIdNav.get(ATTR_RESULTS);
	if (results.isArray() && results.size() > 0) {
		String nationalId = null;
		String cuil = null;

		for (JsonNode r : results) {
			if (r.hasNonNull(ATTR_METADATA) && r.hasNonNull(ATTR_NATIONAL_ID)) {
				JsonNode metadata = r.get(ATTR_METADATA);
				String value = r.get(ATTR_NATIONAL_ID).asText();

				if (metadata.hasNonNull(ATTR_URI)) {
					String uri = metadata.get(ATTR_URI).toString();

					if (uri.contains("cardType='DNI'")) {
						System.out.println("Getting DNI.");
						nationalId = value;
					} else if (uri.contains("cardType='cuil'")) {
						System.out.println("Getting CUIL.");
						cuil = value;

						// También podemos usar CUIL para extraer DNI si aún no se obtuvo
						if (nationalId == null) {
							System.out.println("Getting DNI from CUIL.");
							nationalId = extractDNIFromCUIL(value);
						}
					}
				}
			}
		}

		// Agregamos atributos al builder
		addAttr(builder, ATTR_NATIONAL_ID, nationalId);
		addAttr(builder, ATTR_CUIL, cuil);
	}
}
	
	private String extractDNIFromCUIL(String cuil) {
		Matcher m = DNI_MATCHER.matcher(cuil);
		if(m.find()) {
			logger.ok("extractDNIFromCUIL: Value found: {0}", m.group(1));
			return m.group(1);
		}
		return "";
	}
	
	/**
	 * Extracts user attributes from employmentNav object.
	 * @param builder
	 * @param employmentNav
	 * @return
	 */
	private void getAttrsFromEmploymentNav(ConnectorObjectBuilder builder, JsonNode employmentNav) {
		logger.info("Getting user attrs from json attribute employmentNav");
		getDateIfExists(employmentNav, ATTR_END_DATE, builder);
		
			if (employmentNav.hasNonNull(ATTR_PERSON_NAV)) {
				JsonNode personNav = employmentNav.get(ATTR_PERSON_NAV);
				getAttrsFromPersonNav(builder, personNav);
			}
	}
	
	/**
	 * Extracts firstName and lastName from personalInfoNav object.
	 * @param builder
	 * @param personalInfoNav
	 * @return
	 */
	 private void getAttrsFromPersonalInfoNav(ConnectorObjectBuilder builder, JsonNode personalInfoNav) {
		logger.info("Getting user attrs from json attribute personalInfoNav.");

		if (!personalInfoNav.hasNonNull(ATTR_RESULTS)) {return;}

		JsonNode results = personalInfoNav.get(ATTR_RESULTS);
		if (results.isArray() && results.size() > 0) {
			JsonNode firstResult = results.get(0);
			getIfExists(firstResult, ATTR_FIRST_NAME, builder);
			getIfExists(firstResult, ATTR_LAST_NAME, builder);
		}
	}
	
	/**
	 * Extracts user attributes from customString17Nav object.
	 * @param builder
	 * @param customString17Nav
	 * @return
	 */
	private void getAttrsFromCustomStringNav(ConnectorObjectBuilder builder, JsonNode customString17Nav) {
		
			if (customString17Nav.hasNonNull(ATTR_CUSTOM_STRING_NAV_TITLE_DESC)) {
				JsonNode customString17NavDesc = customString17Nav.get(ATTR_CUSTOM_STRING_NAV_TITLE_DESC);
				addAttr(builder, ATTR_TITLE, customString17NavDesc.asText());
			}
	}
	
}