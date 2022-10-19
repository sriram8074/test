package aemapi;


import static aemapi.Constants.OAUTH;
import  static com.amazonaws.kendra.connector.aem.util.Constants.ONPREM;
import  static com.amazonaws.kendra.connector.aem.util.Constants.CLOUD;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import ucar.httpservices.HTTPSession.RetryHandler;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.NoHttpResponseException;
import org.apache.http.StatusLine;
import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.fluent.Executor;
import org.apache.http.client.fluent.Request;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

public class AemAccess {

	private static String AEM_ENDPOINT;
	
	static HttpRequestRetryHandler requestRetryHandler = new HttpRequestRetryHandler() {
	  	@Override
		public boolean retryRequest(IOException exception, int executionCount, HttpContext arg2) {
			  // retry a max of 5 times
	        if (executionCount >= 5) return false;

	        if (exception instanceof NoHttpResponseException) {
	            // Retry if the server dropped connection on us
	            return true;
	        }

			return false;
		}
	};

		private static final Executor executor = Executor.newInstance(HttpClients.custom()
				.setDefaultRequestConfig(
						RequestConfig.custom().setCookieSpec(CookieSpecs.STANDARD).build()).setRetryHandler(requestRetryHandler)
				.build());


		public static void setAemEndpoint(String aemEndpoint) {
			AEM_ENDPOINT = aemEndpoint;
		}

		public static final String QUERY_BUILDER_ENDPOINT = "/bin/querybuilder.json";

		public static String getAemEndpoint() {
			return AEM_ENDPOINT;
		}

		protected static JsonObject getToJsonObject(String uri) throws IOException {
			return toJsonObject(requestGet(uri));
		}


		protected static JsonObject getToJsonObject(URI uri) throws IOException {
			return toJsonObject(requestGet(uri)); 
		}



		protected static InputStream getToInputStream(URI uri) throws IOException {
			return sendInputStreamRequest(Request.Get(uri)); 
		}


		private static HttpResponse requestGet(String uri) throws IOException {
			return sendRequest(Request.Get(uri));
		}


		private static HttpResponse requestGet(URI uri) throws IOException { return
				sendRequest(Request.Get(uri)); 
		}


		private static JsonObject toJsonObject(HttpResponse response)
				throws IOException {
			JsonObject json = null;
			if (response.getStatusLine().getStatusCode() == 300) {
				return json;
			}
			json = new Gson().fromJson(toString(response),				
					JsonObject.class);
			if (AemHttpClient.isDebugEnabled()) {
				System.out.println("Json> " + json.toString());
			}
			if (checkError(json)) {
				return null;
			}
			return json;
		}

		private static boolean checkError(JsonObject json) {
			if (json.get("error") == null) {
				return false;
			}
			String errorCode = (json.get("error_code") != null)
					? json.get("error_code").getAsString()
							: "";
			String error = (json.get("error") != null)
					? json.get("error").getAsString()
							: "";
			String errorDescription = (json.get("error_description") != null)
					? json.get("error_description").getAsString()
							: "";
			System.out.println(
					"Error> " + errorCode + " " + error + " (" + errorDescription + ")");
			return true;
		}

		private static HttpResponse sendRequest(Request req) throws IOException {
			String token;
			String userName;
			String password;
			AemHttpClient.getDatabaseType();
			if (AemHttpClient.isDebugEnabled()) {
				System.out.println(System.lineSeparator() + "Request> " + req.toString());
			}
			/*
			 * if (AemHttpClient.getDatabaseType().equals(ONPREM) &&
			 * AemHttpClient.getAuthType().equals(OAUTH)) { token =
			 * AemHttpClient.getBearerToken(); req.addHeader(HttpHeaders.AUTHORIZATION,
			 * token); } else { userName = AemHttpClient.getUserName(); password =
			 * AemHttpClient.getPassword(); String credentials = userName + ":" + password;
			 * byte[] encodedBytes =
			 * Base64.encodeBase64(credentials.getBytes(StandardCharsets.UTF_8)); String s =
			 * new String(encodedBytes, StandardCharsets.UTF_8);
			 * req.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + s); }
			 */
			if (AemHttpClient.getAuthType().equals(OAUTH)) {
				token = AemHttpClient.getDatabaseType().equals(CLOUD)?AemHttpClient.getCloudBearerToken():AemHttpClient.getBearerToken();
				System.out.println("aem acess class token one:" + token);
				req.addHeader(HttpHeaders.AUTHORIZATION, token);
			} else {
				userName = AemHttpClient.getUserName();
				password = AemHttpClient.getPassword();
				String credentials = userName + ":" + password;
				byte[] encodedBytes = Base64.encodeBase64(credentials.getBytes(StandardCharsets.UTF_8));
				String s = new String(encodedBytes, StandardCharsets.UTF_8);
				req.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + s);
			}
			HttpResponse response = executor.execute(req).returnResponse();
			StatusLine statusLine = response.getStatusLine();
			if (statusLine.getStatusCode() == 401) {
				retryToken();
			}
			if (AemHttpClient.isDebugEnabled()) {
				System.out.println("Response> " + response.getStatusLine().toString()
						+ " " + response.getEntity().toString());
			}
			handleErrorResponse(response);
			return response;
		}

		private static void retryToken() {
			// TODO Auto-generated method stub
			
		}

		private static InputStream sendInputStreamRequest(Request req) throws IOException {
			String token;
			String userName;
			String password;
			AemHttpClient.getDatabaseType();
			if (AemHttpClient.isDebugEnabled()) {
				System.out.println(System.lineSeparator() + "Request> " + req.toString());
			}
			/*
			 * if (AemHttpClient.getDatabaseType().equals(ONPREM) &&
			 * AemHttpClient.getAuthType().equals(OAUTH)) { token =
			 * AemHttpClient.getBearerToken(); req.addHeader(HttpHeaders.AUTHORIZATION,
			 * token); } else { userName = AemHttpClient.getUserName(); password =
			 * AemHttpClient.getPassword(); String credentials = userName + ":" + password;
			 * byte[] encodedBytes =
			 * Base64.encodeBase64(credentials.getBytes(StandardCharsets.UTF_8)); String s =
			 * new String(encodedBytes, StandardCharsets.UTF_8);
			 * req.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + s); }
			 */
			if (AemHttpClient.getDatabaseType().equals(CLOUD) && AemHttpClient.getAuthType().equals(OAUTH)) {
				token = AemHttpClient.getCloudBearerToken();
				System.out.println("aem acess class token:" + token);
				req.addHeader(HttpHeaders.AUTHORIZATION, token);
			} else {
				userName = AemHttpClient.getUserName();
				password = AemHttpClient.getPassword();
				String credentials = userName + ":" + password;
				byte[] encodedBytes = Base64.encodeBase64(credentials.getBytes(StandardCharsets.UTF_8));
				String s = new String(encodedBytes, StandardCharsets.UTF_8);
				req.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + s);
			}
			HttpResponse response = executor.execute(req).returnResponse();
			StatusLine statusLine = response.getStatusLine();
			if (statusLine.getStatusCode() != 200) {
				return null;
			}
			HttpEntity httpEntity = response.getEntity();
			String str = EntityUtils.toString(httpEntity);

			InputStream targetStream = new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8));
			return targetStream;
		}

		private static void handleErrorResponse(HttpResponse response)
				throws HttpResponseException {
			StatusLine statusLine = response.getStatusLine();
			if (statusLine.getStatusCode() != 200 && statusLine.getStatusCode() != 300) {
				throw new HttpResponseException(statusLine.getStatusCode(),
						statusLine.getReasonPhrase());
			}
		}

		private static String toString(HttpResponse response) throws IOException {
			return EntityUtils.toString(response.getEntity());
		}

	}
