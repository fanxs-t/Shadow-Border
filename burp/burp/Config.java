package burp;

import java.io.*;
import org.json.JSONException;
import org.json.JSONObject;

public class Config {
    private JSONObject configuration;
    public Config(String pluginPath){
        String path = pluginPath.substring(0, pluginPath.lastIndexOf(".jar"));
        String configFile = path + "/../../conf/conf.json";
        String content = readFromTextFile(configFile);
        if(setConfiguration(content)){
            BurpExtender.log("stdout", "Success in loading the configuration file");
        }
    }

    public Object get(String key){
        if(this.configuration.has(key)){
            try {
                return this.configuration.get(key);
            } catch (JSONException e) {
                BurpExtender.log("stderror", String.format("Fail to get %s in the configuration",key));
            }
        }
        return null;
    }

    private String readFromTextFile(String pathname){
        String content = "";
        try{
            File filename = new File(pathname);
            InputStreamReader reader = new InputStreamReader(new FileInputStream(filename));
            BufferedReader br = new BufferedReader(reader);
            String tempString = "";
            while ((tempString = br.readLine()) != null) {
               content += tempString;
            }
        }catch (IOException e){
            BurpExtender.log("stderror", "Cannot read the configuration file.");
            return "";
        }
        return content;
    }

    private Boolean setConfiguration(String content){
        if(!content.equals("")){
            try {
                this.configuration = new JSONObject(content);
                return true;
            }catch (Exception e){
                BurpExtender.log("stderror", "Cannot load the configuration file.");
                BurpExtender.log("stderror", e.getMessage());
            }
        }
        return false;
    }

    public static void main(String[] args){
        try{
            Config configuration = new Config("D:\\Security\\Swords\\Chaldea\\ShadowBorder\\burp\\burp.jar");
        }catch(Exception e){
            System.out.println(e.toString());
        }
    }
}

