/**
 * Created by c0untd0wn on 7/17/15.
 */

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.net.ssl.HttpsURLConnection;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class NaverAuth {
    // Singleton
    private static NaverAuth ourInstance = new NaverAuth();

    public static NaverAuth getInstance() {
        return ourInstance;
    }

    private NaverAuth() {
        this.result = NOTHING;
    }

    private String id;
    private String password;

    private String keyname;
    private String encpw;

    private int result;

    public static final int NOTHING = 0;
    public static final int UNKNOWN_ERROR = 0;
    public static final int LOGIN_SUCCESS = 1;
    public static final int ENCRYPTION_ERROR = 2;
    public static final int WRONG_ID_OR_PASSWORD = 3;
    public static final int CONNECTION_ERROR = 4;

    private static final String COOKIES_HEADER = "Set-Cookie";
    private static CookieManager cookieManager;

    private List<String> cookies = new ArrayList<String>();


    private void doRSAEncryption() {
        URL naverKeys = null;
        URL nidGet = null;
        try {
            // Get Keys (sessionkey, keyname, modulus, exponent)
            naverKeys = new URL("https://nid.naver.com/login/ext/keys.nhn");
            URLConnection nk = naverKeys.openConnection();
            BufferedReader in = new BufferedReader(new InputStreamReader(nk.getInputStream()));
            // Response is only one line
            String resp = in.readLine();
            in.close();

            // Split keys
            String[] keys = resp.split(",");

            String sessionkey = keys[0];
            String keyname = keys[1];
            this.keyname = keyname;
            String evalue = keys[2];
            String nvalue = keys[3];

            // Convert Hex to BigInteger(Dec)
            BigInteger modulus = new BigInteger(evalue, 16);
            BigInteger exponent = new BigInteger(nvalue, 16);

            // Generate message to encrypt
            String message = Character.toString((char)sessionkey.length()) + sessionkey + Character.toString((char)id.length()) + id + Character.toString((char)password.length()) + password;

            // RSA encryption using public key
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(modulus, exponent);
            RSAPublicKey key = (RSAPublicKey) keyFactory.generatePublic(pubKeySpec);

            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding"); //NoPadding
            cipher.init(Cipher.ENCRYPT_MODE, key);
            // Bytes to HexString
            byte[] cipherData = cipher.doFinal(message.getBytes());
            this.encpw = Hex.encodeHexString(cipherData);
        } catch (Exception e) {
            e.printStackTrace();
            result = ENCRYPTION_ERROR;
        }

    }

    // Method used for generating String of POST parameters from HashMap
    private String getPostDataString(HashMap<String, String> params) throws UnsupportedEncodingException{
        StringBuilder result = new StringBuilder();
        boolean first = true;
        for(Map.Entry<String, String> entry : params.entrySet()){
            if (first)
                first = false;
            else
                result.append("&");

            result.append(URLEncoder.encode(entry.getKey(), "UTF-8"));
            result.append("=");
            result.append(URLEncoder.encode(entry.getValue(), "UTF-8"));
        }

        return result.toString();
    }

    private boolean isRedirected(int responseCode) {
        if(responseCode != HttpsURLConnection.HTTP_OK) {
            if(responseCode == HttpsURLConnection.HTTP_MOVED_TEMP
                    || responseCode == HttpsURLConnection.HTTP_MOVED_PERM
                    || responseCode == HttpsURLConnection.HTTP_SEE_OTHER)
                return true;
        }
        return false;
    }

    private String sendRequest(String location) {
        URL url = null;
        try {
            url = new URL(location);

            if(location.startsWith("https://")) {
                HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setReadTimeout(15000);
                conn.setConnectTimeout(15000);
                conn.setDoInput(true);
                conn.setDoOutput(true);
                conn.setInstanceFollowRedirects(false);
                conn.setRequestProperty("Accept", "text/html");
                conn.setRequestProperty("Connection", "keep-alive");

                String line;
                BufferedReader br=new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String response = "";
                while ((line=br.readLine()) != null) {
                    response+=line;
                }

                int responseCode = conn.getResponseCode();
                if(isRedirected(conn.getResponseCode())) {
                    return conn.getHeaderField("location");
                } else {
                    return response.split("\"")[1];
                }
            }
            else {
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setReadTimeout(15000);
                conn.setConnectTimeout(15000);
                conn.setDoInput(true);
                conn.setDoOutput(true);
                conn.setInstanceFollowRedirects(false);
                conn.setRequestProperty("Accept", "text/html");
                conn.setRequestProperty("Connection", "keep-alive");

                String line;
                BufferedReader br=new BufferedReader(new InputStreamReader(conn.getInputStream()));
                String response = "";
                while ((line=br.readLine()) != null) {
                    response+=line;
                }

                int responseCode = conn.getResponseCode();
                if(isRedirected(conn.getResponseCode())) {
                    return conn.getHeaderField("location");
                } else {
                    return response.split("\"")[1];
                }
            }

        } catch (MalformedURLException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    private void logIn() {
        URL naverKeys = null;
        String response = "";

        try {
            naverKeys = new URL("https://nid.naver.com/nidlogin.login");
            HttpsURLConnection conn = (HttpsURLConnection) naverKeys.openConnection();
            conn.setRequestMethod("POST");
            conn.setReadTimeout(15000);
            conn.setConnectTimeout(15000);
            conn.setDoInput(true);
            conn.setDoOutput(true);
            conn.setInstanceFollowRedirects(false);

            conn.setRequestProperty("Connection", "keep-alive");
            conn.setRequestProperty("Referer", "https://nid.naver.com/nidlogin.login");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            HashMap<String, String> params = new HashMap<String, String>();
            params.put("enctp", "1");
            params.put("encnm", this.keyname);
            params.put("url", "http://www.naver.com");
            params.put("smart_LEVEL", "-1");
            params.put("encpw", this.encpw);

            OutputStream os = conn.getOutputStream();
            BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os, "UTF-8"));
            writer.write(getPostDataString(params));
            writer.flush();
            writer.close();
            os.close();

            cookies = conn.getHeaderFields().get("Set-Cookie");
            int responseCode = conn.getResponseCode();

            String location = "";

            if(isRedirected(responseCode)) {
                //location = conn.getHeaderField("location");
                throw new Exception("Redirected to somewhere");
            } else if(responseCode == HttpsURLConnection.HTTP_OK) {

                String line;
                BufferedReader br=new BufferedReader(new InputStreamReader(conn.getInputStream()));
                response = "";
                while ((line=br.readLine()) != null) {
                    response+=line;
                }

                // A division with id=err_common shows the error message when signing in fails
                if(response.contains("err_common")) {
                    this.result = WRONG_ID_OR_PASSWORD;
                    return;
                }
                else if(response.contains("sso/finalize.nhn")) {
                    // TODO: better use regex for finding redirection url
                    location = response.split("\"")[1];
                }
            } else {
                throw new Exception(responseCode + "");
            }
            // Goes to www.naver.com
            location = sendRequest(location);

            if(location.startsWith("http://www.naver.com")) {
                this.result = LOGIN_SUCCESS;
            } else {
                this.result = UNKNOWN_ERROR;
            }

        } catch (Exception e) {
            this.result = CONNECTION_ERROR;
            e.printStackTrace();
        }
    }

    public int signIn(String id, String password) {
        this.id = id;
        this.password = password;

        this.cookieManager = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        CookieHandler.setDefault(this.cookieManager);

        doRSAEncryption();
        if(this.result == NOTHING)
            logIn();
        return this.result;
    }

    public CookieManager getCookieManager() {
        return this.cookieManager;
    }

    public List<HttpCookie> getCookies() {
        return this.cookieManager.getCookieStore().getCookies();
    }

    public HashMap<String, String> getCookiesAsHashMap() {
        List<HttpCookie> cookieList = this.cookieManager.getCookieStore().getCookies();
        HashMap<String, String> cookieHashMap = new HashMap<String, String>();

        for(HttpCookie cookie: cookieList) {
            String cookieString = cookie.toString();
            int indexOfEqual = cookieString.indexOf("=");

            String key = cookieString.substring(0, indexOfEqual);
            String value = cookieString.substring(indexOfEqual + 1);

            cookieHashMap.put(key, value);
        }

        return cookieHashMap;
    }

    public List<String> getCookiesAsListOfString() {
        List<HttpCookie> cookieList = this.cookieManager.getCookieStore().getCookies();
        List<String> cookieStringList = new ArrayList<String>();

        for(HttpCookie cookie: cookieList) {
            String cookieString = cookie.toString();

            cookieStringList.add(cookieString);
        }

        return cookieStringList;
    }
}
