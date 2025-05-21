import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        String banner = "Xshell全版本凭证一键导出工具!(支持Xshell 7.0+版本)" +
                "\nJava版本xshell解密，需要提供目标主机userSID和用户名" +
                "\nCMD执行whoami /all" +
                "\n示例: java -jar Java_Xshell_Decrypt.jar 127.0.0.1.xsh S-1-5-21-3062573386-3401232805-1991892280-500 Administrator\n";
        if (args.length != 3) {
            System.out.println("输入参数错误！");
            System.out.println(banner);
        }
        else {
            XClass.Decrypt(args[0], args[1], args[2]);
            System.out.println("[*] read done!");
        }
        //XClass.xdecrypt("/Users/w1nd/Desktop/2.xsh","S-1-5-21-3062573386-3501242805-1991882280-500","Administrator");

    }
}