package com.rakkau.connectors;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.OperationTimeoutException;
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException;
import org.identityconnectors.framework.common.exceptions.PreconditionFailedException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class HttpUtils {

	private static final Log LOG = Log.getLog(HttpUtils.class);
	private CloseableHttpClient client;
	private SuccessFactorsConfiguration config;
	private ObjectMapper jsonMapper;
	private String basicToken;

	public HttpUtils(CloseableHttpClient client, SuccessFactorsConfiguration config) {
		this.client = client;
		this.config = config;
		this.jsonMapper = new ObjectMapper();
	}

	public CloseableHttpClient getClient() {
		return client;
	}

	public void setClient(CloseableHttpClient client) {
		this.client = client;
	}

	protected JsonNode callRequest(HttpRequestBase request) {

		LOG.ok("Request URI: {0}", request.getURI());

		CloseableHttpResponse response;
		try {
			response = this.getClient().execute(request);
		} catch (IOException e) {
			throw new ConnectorException("Error executing request on " + request.getURI(), e);
		}
		LOG.ok("Response: {0}", response.getStatusLine());

		LOG.ok("Processing response codes");
		this.processResponseErrors(response);

		String result;
		try {
			result = EntityUtils.toString(response.getEntity());
			LOG.ok("Response body: {0}", result);
		}
		catch(IOException io) {
			throw new ConnectorException("Error reading api response.", io);
		}
		finally {
			closeResponse(response);
		}
		try {
			return jsonMapper.readTree(result);
		}
		catch(IOException jpe) {
			LOG.error("Error parsing json response. Returning empty json", jpe);
			return this.jsonMapper.createObjectNode();
		}
	}

	public void processResponseErrors(CloseableHttpResponse response) {
		int statusCode = response.getStatusLine().getStatusCode();
		if (statusCode >= 200 && statusCode <= 299) {
			return;
		}
		String responseBody = null;
		try {
			responseBody = EntityUtils.toString(response.getEntity());
		} catch (IOException e) {
			LOG.warn("cannot read response body: " + e, e);
		}

		String message = "HTTP error " + statusCode + " : " + responseBody;
		LOG.error("{0}", message);
		if (statusCode == 400 || statusCode == 405 || statusCode == 406) {
			closeResponse(response);
			throw new ConnectorIOException(message);
		}
		if (statusCode == 401 || statusCode == 402 || statusCode == 403 || statusCode == 407) {
			closeResponse(response);
			throw new PermissionDeniedException(message);
		}
		if (statusCode == 404 || statusCode == 410) {
			closeResponse(response);
			throw new UnknownUidException(message);
		}
		if (statusCode == 408) {
			closeResponse(response);
			throw new OperationTimeoutException(message);
		}
		if (statusCode == 409) {
			closeResponse(response);
			throw new AlreadyExistsException();
		}
		if (statusCode == 412) {
			closeResponse(response);
			throw new PreconditionFailedException(message);
		}
		if (statusCode == 418) {
			closeResponse(response);
			throw new UnsupportedOperationException("Sorry, no cofee: " + message);
		}
		// TODO: other codes
		closeResponse(response);
		throw new ConnectorException(message);
	}

	protected void closeResponse(CloseableHttpResponse response) {
		// to avoid pool waiting
		try {
			response.close();
		} catch (IOException e) {
			LOG.warn(e, "Error when trying to close response: " + response);
		}
	}

	public static String encodeURI(String input) {
		try {
			return URLEncoder.encode(String.join(" and ", input), StandardCharsets.UTF_8.toString());
		}
		catch(UnsupportedEncodingException e) {
			LOG.error("It should not happen because UTF8 is a standard", e);
			return input;
		}
	}

}