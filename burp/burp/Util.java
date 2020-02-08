package burp;
import burp.Redis;
import org.bouncycastle.util.encoders.Base64;
import org.json.JSONObject;
import java.math.BigInteger;
import java.net.URL;
import java.security.MessageDigest;
import java.util.*;


public class Util {
    public Redis redis;

    public Util() throws Exception{
        this.redis = new Redis();
    }

    public static String requestParse(IRequestInfo reqInfo, byte[] request, String protocol, Integer port) throws Exception{
        Map<String,String> parseResult = new HashMap<String, String>();
        // Hedaers
        List<String> headers = reqInfo.getHeaders();
        JSONObject headersJson = new JSONObject();
        for (String h:headers.subList(1, headers.size())) {
            int index = h.indexOf(":", 0);
            String header = h.substring(0,index).trim();
            String value = h.substring(index+1, h.length()).trim();
            headersJson.put(header, value);
        }
        String headersString = headersJson.toString();
        parseResult.put("headers", headersString);
        // Host And Url
        // www.example.com/test?a=1&b=1
        URL getUrl = reqInfo.getUrl();
        parseResult.put("host", getUrl.getHost());           //    www.example.com
        if(getUrl.getQuery()!=null){                         //    a=1&b=1 ( probably null )
            parseResult.put("query", getUrl.getQuery());
        }else{
            parseResult.put("query", "");
        }
        parseResult.put("path", getUrl.getPath());           //    /test
        // Method
        parseResult.put("method", reqInfo.getMethod());
        //POST data
        int bodyOffest = reqInfo.getBodyOffset();
        String postdata = new String(Arrays.copyOfRange(request, bodyOffest, request.length));
        parseResult.put("postdata", postdata);
        // Raw request
        String requestRaw = new String(Base64.encode(request));
        parseResult.put("requestRaw", requestRaw);
        // protocol
        parseResult.put("protocol", protocol);              // http https
        //port
        parseResult.put("port", String.valueOf(port));
        //base64
        String packetJson = new JSONObject(parseResult).toString();
        String packetString = new String(Base64.encode(packetJson.getBytes()));
        //Get the hash signature of each request
        String reqhash = getHash(parseResult.get("protocol"), parseResult.get("host"), parseResult.get("port"), parseResult.get("path"), parseResult.get("method"), parseResult.get("query"));
        return String.format("%s;%s", reqhash, packetString);
    }

    // The hash digest of "protocl:protocl,host:host,port:port,path:path,method:method,query:parameters"
    public static String getHash(String protocol, String host, String port, String path, String method, String query) throws Exception{
        // Get the parameters in the query
        List<String> parameterList = new ArrayList<String>();
        String[] queryArray = query.split("&");
        for(String tmp:queryArray){
            String[] keyAndvalue = tmp.split("=");
            parameterList.add(keyAndvalue[0]);
        }
        Collections.sort(parameterList);
        String parameters = parameterList.toString();

        String plaintext = String.format("protocol:%s,host:%s,port:%s,path:%s,method:%s,query:%s",protocol,host,port,path,method,parameters);
        MessageDigest m = MessageDigest.getInstance("MD5");
        m.update(plaintext.getBytes("UTF8"));
        byte[] MD5Bytes = m.digest();
        return(new BigInteger(1, MD5Bytes).toString(16));
    }

    public static void main(String[] args){
        try{
            String result = getHash("http","1", "80","2","3","4");
            System.out.println(result);
        }catch(Exception e){
            System.out.println(e.toString());
        }
    }
}
