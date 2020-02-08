package burp;
import redis.clients.jedis.*;


public class Redis {
    private Jedis jedis;
    private String host;
    private String password;
    private Integer port = 6379;

    public Redis(){
        host = (String) BurpExtender.configuration.get("redis_host");
        password = (String) BurpExtender.configuration.get("redis_pass");
        String tmp = (String) BurpExtender.configuration.get("redis_port");
        if(tmp!=null){
            port = Integer.valueOf(tmp);
        }
        this.jedis = new Jedis(host, port);
        if(!password.isEmpty()) {
            this.jedis.auth(password);
        }
    }
    public String RedisTask(String reqhash, String packet) throws Exception{
        if(this.jedis.ping().equals("PONG")){
            if(this.jedis.hsetnx("request", reqhash, packet)>0){
                BurpExtender.log("stdout", "---------------------------------------\n"+String.format("[*] Add Task:%s, packet:%s",reqhash,packet)+"\n---------------------------------------\n");
                this.jedis.lpush("waiting", reqhash);
            }
            return reqhash;
        }else{
            BurpExtender.log("stderror", "[!] Redis not responding.");
            return "False";
        }
    }

    public static void main(String[] args){
        try{
            //System.out.println(getHash("baike.baidu.com","https://123/item/www/109924","GET","dwaii=31&fafw=123&aa=1&a=1&b=2&c=3&d=4"));
        }catch(Exception e){
            System.out.println(e.toString());
        }
    }
}