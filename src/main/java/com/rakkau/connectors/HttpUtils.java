package com.rakkau.connectors;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.http.Consts;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.*;
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
	private Runnable tokenRefreshCallback;

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

	public void setTokenRefreshCallback(Runnable cb) {
		this.tokenRefreshCallback = cb;
	}

	private HttpRequestBase cloneRequest(HttpRequestBase request) {
		HttpRequestBase newRequest;

		// Crear instancia según el tipo de request original
		if (request instanceof HttpGet) {
			newRequest = new HttpGet(request.getURI());
		} else if (request instanceof HttpPost) {
			newRequest = new HttpPost(request.getURI());
		} else if (request instanceof HttpPut) {
			newRequest = new HttpPut(request.getURI());
		} else if (request instanceof HttpDelete) {
			newRequest = new HttpDelete(request.getURI());
		} else if (request instanceof HttpPatch) {
			newRequest = new HttpPatch(request.getURI());
		} else if (request instanceof HttpHead) {
			newRequest = new HttpHead(request.getURI());
		} else if (request instanceof HttpOptions) {
			newRequest = new HttpOptions(request.getURI());
		} else {
			throw new UnsupportedOperationException(
					"cloneRequest() does not support request type: " + request.getClass()
			);
		}

		// Copiar headers
		for (org.apache.http.Header header : request.getAllHeaders()) {
			if (!header.getName().equalsIgnoreCase("Authorization")) {
				newRequest.addHeader(header.getName(), header.getValue());
			}
		}

		// Copiar entidad si la request original tiene cuerpo
		if (request instanceof HttpEntityEnclosingRequestBase) {
			HttpEntityEnclosingRequestBase orig = (HttpEntityEnclosingRequestBase) request;
			HttpEntityEnclosingRequestBase cloned = (HttpEntityEnclosingRequestBase) newRequest;

			if (orig.getEntity() != null) {
				try {
					// Convertir la entidad en bytes y copiarla
					byte[] bytes = EntityUtils.toByteArray(orig.getEntity());
					cloned.setEntity(new ByteArrayEntity(bytes));
				} catch (IOException e) {
					throw new RuntimeException("Error cloning request entity", e);
				}
			}
		}

		return newRequest;
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

		int statusCode = response.getStatusLine().getStatusCode();

		if (statusCode == 403) {
			try {
				String body = EntityUtils.toString(response.getEntity());
				if (body.contains("[LGN0022]") && body.contains("access token has expired")) {

					LOG.info("Se detectó token expirado con error (LGN0022). Refreshing token...");

					if (this.tokenRefreshCallback != null) {
						this.tokenRefreshCallback.run();
					} else {
						LOG.error("tokenRefreshCallback is not set! Cannot refresh token.");
					}

					closeResponse(response);

					LOG.warn("Se hizo una llamada con un token vencido. Reintentando la llamada con el nuevo token");

					// Se reintenta la request original con nuevo token
					HttpRequestBase cloned = cloneRequest(request);
					cloned.removeHeaders("Authorization");
					cloned.addHeader("Authorization", "Bearer " + SuccessFactorsConnector.accessToken);

					return callRequest(cloned);
				}
			} catch (IOException e) {
				throw new ConnectorException("Error while parsing 403 body.", e);
			}
		}

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