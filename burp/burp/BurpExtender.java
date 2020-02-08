package burp;
import java.io.*;
import java.util.Arrays;
import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener{
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    private String extensionName;
    private String version;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static String path;
    public static Config configuration;

    public BurpExtender() {
        this.extensionName = "Shadow Border";
        this.version = "v1.0.0";
    }

    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(String.format("%s %s", this.extensionName, this.version));
        callbacks.registerContextMenuFactory((IContextMenuFactory)new Menu());
        callbacks.registerHttpListener((IHttpListener) this);
        BurpExtender.stdout = new PrintWriter(callbacks.getStdout(), true);
        BurpExtender.stderr = new PrintWriter(callbacks.getStderr(), true);
        BurpExtender.path = callbacks.getExtensionFilename();
        BurpExtender.stdout.println(this.getBanner());
        BurpExtender.configuration = new Config(path);
    }

    public void processHttpMessage(final int toolFlag, final boolean messageIsRequest, final IHttpRequestResponse messageInfo) {
        // Only accept Proxy Meesage (4)
        //if (messageIsRequest && toolFlag == 4) {
        if (messageIsRequest) {
            final IRequestInfo reqInfo = BurpExtender.helpers.analyzeRequest(messageInfo);
            final IHttpService iHttpService = messageInfo.getHttpService();
            final byte[] request  = messageInfo.getRequest();
            final String allowedMethods = (String)BurpExtender.configuration.get("scan_methods");
            final List<String> allowedMethodsList = Arrays.asList(allowedMethods.split(","));
            if (allowedMethodsList.contains(reqInfo.getMethod())) {
                try{
                    Util util = new Util();
                    String protocol = iHttpService.getProtocol();
                    Integer port = iHttpService.getPort();
                    String[] parseResult = util.requestParse(reqInfo, request, protocol, port).split(";");
                    util.redis.RedisTask(parseResult[0], parseResult[1]);
                }catch (Exception e){
                    log("stderror","[!] Fail in parseResult or RedisTask;");
                    log("stderror",e.toString());
                }
            }
        }
    }

    public String getBanner() {
        final String bannerInfo = "[+] ##############################################\n[+]    " + this.extensionName + " "+ this.version + "\n[+]    Anthor: Fanxs\n[+] ##############################################";
        return bannerInfo;
    }

    public static void log(String type, String message){
        if(type.equals("stdout")){
            BurpExtender.stdout.println(message);
        }else{
            BurpExtender.stderr.println(message);
        }
    }

    public static void main(String[] args){
        try{
            //String result = Lib.jedis.RedisTask("/123","GET");
            System.out.println("1");
        }catch(Exception e){
            System.out.println(e.toString());
        }
    }
}