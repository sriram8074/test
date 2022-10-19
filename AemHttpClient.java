package aemapi;

import static aemapi.Constants.GRANT_TYPE;
import static aemapi.Constants.REDIRECT_URI;
import static aemapi.Constants.SLASH_AUTH_SLASH_TOKEN;
import static aemapi.Constants.alg;
import static aemapi.Constants.exchange;
import static aemapi.Constants.exp;
import static aemapi.Constants.iat;
import static aemapi.Constants.metascopes;
import static aemapi.Constants.scope;
import static aemapi.Constants.sub;

import com.amazonaws.kendra.connector.aem.model.repository.AemConfiguration;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import static java.lang.Boolean.TRUE;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import javax.net.ssl.HttpsURLConnection;
import org.json.JSONException;
import org.json.JSONObject;

public class AemHttpClient extends AemAccess {
  private static final AemHttpClient clientInstance = new AemHttpClient();
  private static final boolean isDebugEnabled = false;
  //private static final String clientId = null;
  private static final String admin = null;
 // private static final String OrgId = null;
  private String accessToken;
  private String CloudAccessToken;
  private String authType;
  private String userName;
  private String password;
  private String databaseType;
  private static String clientId;
  private String clientSecret;
  private String privateKey;
  private static String orgId;
  private static String technicalAccountId;
  private static String imsHost;
  
  private static AemConfiguration aemConfiguration;
 // private static final String orgId = aemConfiguration.getOrgId();
	//private static final String technicalAccountId = aemConfiguration.getTechnicalAccountId();
	//private static final String imsHost = aemConfiguration.getImsHost();
	
	//private static final String clientId = aemConfiguration.getClientId();
	//static String aemUrl = aemConfiguration.getAemUrl();
	//final static String aud = aemUrl + SLASH_AUTH_SLASH_TOKEN;

  protected static String getBearerToken() {
    return "Bearer " + clientInstance.accessToken;
  }
  
  protected static String getCloudBearerToken() {
	    return "Bearer " + clientInstance.CloudAccessToken;
	  }

  protected static String getAuthType() {
    return clientInstance.authType;
  }

  /**
   * Method to set authType.
   */
  public static void setAuthType(String authType) {
    Objects.requireNonNull(authType);
    clientInstance.authType = authType;
  }
  
  protected static String getClientId() {
	    return clientInstance.clientId;
	  }
  public static void setClientId(String clientId) {
	    Objects.requireNonNull(clientId);
	    clientInstance.clientId = clientId;
	  }
  
  protected static String getClientSecret() {
	    return clientInstance.clientSecret;
	  }
public static void setClientSecret(String clientSecret) {
	    Objects.requireNonNull(clientSecret);
	    clientInstance.clientSecret = clientSecret;
	  }

protected static String getPrivateKey() {
    return clientInstance.privateKey;
  }
public static void setPrivateKey(String privateKey) {
    Objects.requireNonNull(privateKey);
    clientInstance.privateKey = privateKey;
  }
protected static String getOrgId() {
    return clientInstance.orgId;
  }
public static void setOrgId(String orgId) {
    Objects.requireNonNull(orgId);
    clientInstance.orgId = orgId;
  }

protected static String getTechnicalAccountId() {
    return clientInstance.technicalAccountId;
  }
public static void setTechnicalAccountId(String technicalAccountId) {
    Objects.requireNonNull(technicalAccountId);
    clientInstance.technicalAccountId = technicalAccountId;
  }

protected static String getImsHost() {
    return clientInstance.imsHost;
  }
public static void setImsHost(String imsHost) {
    Objects.requireNonNull(imsHost);
    clientInstance.imsHost = imsHost;
  }
  protected static String getDatabaseType() {
	    return clientInstance.databaseType;
	  }
  public static void setDatabaseType(String databaseType) {
	    Objects.requireNonNull(databaseType);
	    clientInstance.databaseType = databaseType;
	  }
  
  
  
  protected static String getUserName() {
    return clientInstance.userName;
  }

  /**
   * Method to set username.
   */
  public static void setUserName(String userName) {
    Objects.requireNonNull(userName);
    clientInstance.userName = userName;
  }

  protected static String getPassword() {
    return clientInstance.password;
  }

  /**
   * Method to set password.
   */
  public static void setPassword(String password) {
    Objects.requireNonNull(password);
    clientInstance.password = password;
  }

  protected static boolean isDebugEnabled() {
    return clientInstance.isDebugEnabled;
  }

  /**
   * Method to set access token.
   */
  public static void createAndSetAccessToken(String clientId, String clientSecret, String priKey,
       String aemUrl)
      throws IOException, JSONException, InvalidKeySpecException, NoSuchAlgorithmException {
	  Security.addProvider(new BouncyCastleProvider());
    PrivateKey privateKey = getPrivateKey(priKey);
    String jwtToken = generateJwtToken(privateKey, clientId, aemUrl);
    String accessToken = getAccessToken(clientId, clientSecret, aemUrl, jwtToken);
    System.out.println("TOKEN GENERATION METHOD");
    System.out.println("TOKEN GENERATION METHOD");
    System.out.println("TOKEN GENERATION METHOD");
    System.out.println("TOKEN GENERATION METHOD");
    Objects.requireNonNull(accessToken);
    clientInstance.accessToken = accessToken;
    // _verifyToken();
  }
  public static String createAndSetCloudAccessToken(String clientId, String clientSecret, String priKey)
			throws IOException, JSONException, InvalidKeySpecException, NoSuchAlgorithmException {
	  Security.addProvider(new BouncyCastleProvider());
		PrivateKey privateKey = getPrivateKey(priKey);
		String CloudJwtToken = generateCloudJwtToken(privateKey, aemConfiguration);
		String CloudAccessToken = getCloudAccessToken(clientId, clientSecret, CloudJwtToken);
		System.out.println("TOKEN GENERATION METHOD");
	    System.out.println("TOKEN GENERATION METHOD");
	    System.out.println("TOKEN GENERATION METHOD");
	    System.out.println("TOKEN GENERATION METHOD");
		Objects.requireNonNull(CloudAccessToken);
		clientInstance.CloudAccessToken = CloudAccessToken;
		System.out.println(CloudAccessToken);
		// _verifyToken();
		return CloudAccessToken;
	}

  /**
   * Method to fetch AEM access token.
   *
   * @param clientId     - AEM client ID
   * @param clientSecret - AEM client secret
   * @param aemUrl       - AEM url
   * @param token        - JWT token
   * @return - AEM access token
   */
  public static String getAccessToken(String clientId, String clientSecret, String aemUrl,
      String token)
      throws IOException, JSONException {
    String imsExchange = aemUrl + SLASH_AUTH_SLASH_TOKEN;
    URL obj = new URL(imsExchange);
    HttpURLConnection con = (HttpURLConnection) obj.openConnection();
    // add request header
    con.setRequestMethod("POST");
    // Add parameters to request
    String urlParameters =
        "client_id=" + clientId + "&client_secret=" + clientSecret + "&assertion=" + token
            + "&grant_type=" + GRANT_TYPE + "&redirect_uri" + REDIRECT_URI;

    // Send post request
    con.setDoOutput(true);
    DataOutputStream wr = new DataOutputStream(con.getOutputStream());
    wr.writeBytes(urlParameters);
    wr.flush();
    wr.close();
    int responseCode = con.getResponseCode();
    System.out.println("Sending 'POST' request to URL: " + imsExchange);
    System.out.println("Post parameters: " + urlParameters);
    System.out.println("Response Code: " + responseCode);
    boolean responseError = false;
    InputStream is;
    if (responseCode < HttpsURLConnection.HTTP_BAD_REQUEST) {
      is = con.getInputStream();
    } else {
      is = con.getErrorStream();
      responseError = true;
    }
    BufferedReader in = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
    String inputLine;
    StringBuilder response = new StringBuilder();
    while ((inputLine = in.readLine()) != null) {
      response.append(inputLine);
    }
    in.close();
    if (responseError) {
      System.out.println(response.toString());
    }
    JSONObject jsonObject = new JSONObject(response.toString());
    return jsonObject.getString("access_token");
  }
  
  /**
	 * Method to fetch AEM cloud access token.
	 *
	 * @param clientId     - AEM client ID
	 * @param clientSecret - AEM client secret
	 * @param aemUrl       - AEM url
	 * @param token        - JWT token
	 * @return - AEM access token
	 */
	public static String getCloudAccessToken(String clientId, String clientSecret, String jwttoken)
			throws IOException, JSONException {
		//String imsExchange = aemUrl + SLASH_AUTH_SLASH_TOKEN;
		URL obj = new URL(exchange);
		HttpsURLConnection con = (HttpsURLConnection) obj.openConnection();
		// add request header
		con.setRequestMethod("POST");
		// Add parameters to request
		String urlParameters = "client_id=" + clientId + "&client_secret=" + clientSecret + "&jwt_token=" + jwttoken;

		// Send post request
		con.setDoOutput(true);
		DataOutputStream wr = new DataOutputStream(con.getOutputStream());
		wr.writeBytes(urlParameters);
		wr.flush();
		wr.close();
		int responseCode = con.getResponseCode();
		System.out.println("Sending 'POST' request to URL: " + exchange);
		System.out.println("Post parameters: " + urlParameters);
		System.out.println("Response Code: " + responseCode);
		boolean responseError = false;
		InputStream is;
		if (responseCode < HttpsURLConnection.HTTP_BAD_REQUEST) {
			is = con.getInputStream();
		} else {
			is = con.getErrorStream();
			responseError = true;
		}
		BufferedReader in = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8));
		String inputLine;
		StringBuilder response = new StringBuilder();
		while ((inputLine = in.readLine()) != null) {
			response.append(inputLine);
		}
		in.close();
		if (responseError) {
			System.out.println(response.toString());
		}
		JSONObject jsonObject = new JSONObject(response.toString());
		return jsonObject.getString("access_token");
	}

  /**
   * Method to return AEM JWT token.
   *
   * @param privateKey       - AEM private key
   * @param clientId          - AEM Client id
   * @param aemUrl             - AEM url
   * @return - AEM JWT token
   */
  public static String generateJwtToken(PrivateKey privateKey, String clientId, String aemUrl) {
    String token = null;
    final String aud = aemUrl + SLASH_AUTH_SLASH_TOKEN;
    try {
      Map<String, Object> claims = new LinkedHashMap<>();
      claims.put("aud", aud);
      claims.put("iss", clientId);
      claims.put("sub", sub);
      claims.put("iat", iat);
      claims.put("exp", exp);
      claims.put("scope", scope);
      claims.put("cty", "code");
      claims.put("alg", alg);
      token = Jwts.builder().setClaims(claims).signWith(SignatureAlgorithm.RS256, privateKey)
          .compact();
    } catch (Exception e) {
      e.printStackTrace();
    }
    return token;
  }
  
  /**
	 * Method to return AEM Cloud JWT token.
	 *
	 * @param privateKey      - AEM private key
	 * @param AEMconfiguration - AEM configuration
	 * @return - AEM CloudJWT token
	 */

	public static String generateCloudJwtToken(PrivateKey privateKey, AemConfiguration aemConfiguration) {
		String CloudJwtToken = null;
		String metascopes [] = aemapi.Constants.metascopes.split(",");
		
		
		
		try {
			Map<String, Object> jwtClaims = new LinkedHashMap<>();
			jwtClaims.put("iss", orgId);
			jwtClaims.put("sub", technicalAccountId);
			jwtClaims.put("exp", exp);
			jwtClaims.put("aud", "https://" + imsHost + "/c/" + clientId);
			for(String metascope : metascopes) {
		    jwtClaims.put("https://" + imsHost + "/s/" + metascope,TRUE);
			}

			SignatureAlgorithm sa = SignatureAlgorithm.RS256;
			// Create the final JWT token
			CloudJwtToken = Jwts.builder().setClaims(jwtClaims).signWith(sa, privateKey).compact();
		} catch (Exception e) {
			e.printStackTrace();
		}

			return CloudJwtToken;
		}


  private static PrivateKey getPrivateKey(String rsaPrivateKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(
        Base64.getDecoder().decode(rsaPrivateKey));
    KeyFactory kf = KeyFactory.getInstance("RSA");
    return kf.generatePrivate(keySpec);
  }
}