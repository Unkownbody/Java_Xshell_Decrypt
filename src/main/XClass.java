import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

class XClass {
    static class Xsh {
        String host;
        String userName;
        String password;
        String encryptPw;
        String version;
    }

    static private boolean enableMaterPasswd = false;
    static private String hashMasterPasswd = null;
    public static Boolean Decrypt(String selectPath, String userSID, String userName) throws IOException {
        List<File> xshFiles = processInput(selectPath);
        for (File xshFile : xshFiles) {
            System.out.println("[+]检测文件："+String.valueOf(xshFile));
            Xsh xsh = xshParser(String.valueOf(xshFile));
            if (xsh.encryptPw == null){
                System.out.println("没有发现密码，可能是堡垒机登录或没有保存密码！");
            }else{
                xdecrypt(xsh,userSID,userName);
            }
        }
        return true;
    }


    public static String xdecrypt(Xsh xsh, String userSID, String userName) throws IOException {

        String password = null;
        if (!enableMaterPasswd) {
            if (xsh.version.startsWith("5.0") || xsh.version.startsWith("4") || xsh.version.startsWith("3") || xsh.version.startsWith("2")) {
                try {
                    byte[] data = Base64.getDecoder().decode(xsh.encryptPw);
                    byte[] Key = MessageDigest.getInstance("MD5").digest("!X@s#h$e%l^l&".getBytes(StandardCharsets.US_ASCII));
                    byte[] passData = new byte[data.length - 0x20];
                    System.arraycopy(data, 0, passData, 0, data.length - 0x20);
                    byte[] decrypted = RC4.decrypt(Key, passData);
                    password = new String(decrypted, StandardCharsets.US_ASCII);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            } else if (xsh.version.startsWith("5.1") || xsh.version.startsWith("5.2")) {
                try {
                    byte[] data = Base64.getDecoder().decode(xsh.encryptPw);
                    byte[] Key = MessageDigest.getInstance("SHA-256").digest(userSID.getBytes(StandardCharsets.US_ASCII));
                    byte[] passData = new byte[data.length - 0x20];
                    System.arraycopy(data, 0, passData, 0, data.length - 0x20);
                    byte[] decrypted = RC4.decrypt(Key, passData);
                    password = new String(decrypted, StandardCharsets.US_ASCII);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            } else if (xsh.version.startsWith("5") || xsh.version.startsWith("6") || xsh.version.startsWith("7.0")) {
                try {
                    byte[] data = Base64.getDecoder().decode(xsh.encryptPw);
                    byte[] Key = MessageDigest.getInstance("SHA-256").digest((userName + userSID).getBytes());
                    byte[] passData = new byte[data.length - 0x20];
                    System.arraycopy(data, 0, passData, 0, data.length - 0x20);
                    byte[] decrypted = RC4.decrypt(Key, passData);
                    password = new String(decrypted);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            } else if (xsh.version.startsWith("7")) {
                try {
                    String strkey1 = new StringBuilder(userName).reverse().toString() + userSID;
                    String strkey2 = new StringBuilder(strkey1).reverse().toString();
                    byte[] data = Base64.getDecoder().decode(xsh.encryptPw);
                    byte[] Key = MessageDigest.getInstance("SHA-256").digest(strkey2.getBytes());
                    byte[] passData = new byte[data.length - 0x20];
                    System.arraycopy(data, 0, passData, 0, data.length - 0x20);
                    byte[] decrypted = RC4.decrypt(Key, passData);
                    password = new String(decrypted);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            }
        } else {
            System.out.println("  MasterPassword Enable !");
        }
        System.out.println("  Host: " + xsh.host);
        System.out.println("  UserName: " + xsh.userName);
        System.out.println("  Password: " + password);
        System.out.println("  Version: " + xsh.version);
        return password;
    }

    public static void decryptMasterPw() {
    }
    public static List<File> processInput(String input) {
        List<File> xshFiles = new ArrayList<>();
        File file = new File(input);

        if (!file.exists()) {
            System.out.println("路径/文件不存在: " + input);
            return xshFiles;
        }

        if (file.isFile()) {
            // 判断是否为.xsh文件（不区分大小写）
            if (input.toLowerCase().endsWith(".xsh")) {
                xshFiles.add(file);
                System.out.println("检测到单个XSH文件: " + file.getAbsolutePath());
            } else {
                System.out.println("该文件不是.xsh文件: " + input);
            }
        } else if (file.isDirectory()) {
            // 遍历目录下的所有.xsh文件（不区分大小写）
            File[] files = file.listFiles((dir, name) ->
                    name.toLowerCase().endsWith(".xsh")
            );
            if (files != null && files.length > 0) {
                for (File f : files) {
                    xshFiles.add(f);
                    System.out.println("检测到XSH文件: " + f.getAbsolutePath());
                }
                System.out.println("共找到 " + files.length + " 个XSH文件");
            } else {
                System.out.println("目录中没有XSH文件");
            }
        } else {
            System.out.println("输入的路径既不是文件也不是目录: " + input);
        }
        return xshFiles;
    }
    public static Xsh xshParser(String xshPath) throws IOException {
        Xsh xsh = new Xsh();
        xsh.host = null;
        xsh.userName = null;
        xsh.password = null;
        xsh.version = null;
        xsh.encryptPw = null;
        try (BufferedReader sr = new BufferedReader(new FileReader(xshPath))) {
            String rawPass;
            while ((rawPass = sr.readLine()) != null) {
                if (Pattern.matches("Host=(.*?)", rawPass)) {
                    xsh.host = rawPass.replace("Host=", "");
                }
                if (Pattern.matches("Password=(.*?)", rawPass)) {
                    rawPass = rawPass.replace("Password=", "");
                    rawPass = rawPass.replace("\r\n", "");
                    if (rawPass.isEmpty()) {
                        continue;
                    }
                    xsh.encryptPw = rawPass;
                }
                if (Pattern.matches("UserName=(.*?)", rawPass)) {
                    xsh.userName = rawPass.replace("UserName=", "");
                }
                if (Pattern.matches("Version=(.*?)", rawPass)) {
                    xsh.version = rawPass.replace("Version=", "");
                }
            }
        }
        return xsh;
    }

    public static List<String> enumXshPath(String userDataPath) {
        List<String> xshPathList = new ArrayList<>();
        String sessionsPath;
        if (userDataPath.endsWith("7") || userDataPath.endsWith("6") || userDataPath.endsWith("5")) {
            sessionsPath = userDataPath + "\\Xshell\\Sessions";
        } else {
            sessionsPath = userDataPath;
        }
        File dir = new File(sessionsPath);
        if (dir.exists()) {
            File[] files = dir.listFiles((d, name) -> name.endsWith(".xsh"));
            if (files != null) {
                for (File file : files) {
                    xshPathList.add(file.getAbsolutePath());
                }
            }
        }
        return xshPathList;
    }

    public static List<String> getUserDataPath() {
        System.out.println("[*] Start GetUserPath....");
        List<String> userDataPath = new ArrayList<>();
        // Java 没有直接访问 Windows 注册表的方法，这里需要借助其他库或者方法
        // 暂时假设我们可以通过其他方式获取到注册表信息
        // 下面代码只是示例，实际需要实现注册表访问逻辑
        // ...
        System.out.println("[*] Get UserPath Success !");
        System.out.println();
        return userDataPath;
    }

    public static void checkMasterPw(String userDataPath) throws IOException {
        String masterPwPath = userDataPath + "\\common\\MasterPassword.mpw";
        try (BufferedReader sr = new BufferedReader(new FileReader(masterPwPath))) {
            String rawPass;
            while ((rawPass = sr.readLine()) != null) {
                if (Pattern.matches("EnblMasterPasswd=(.*?)", rawPass)) {
                    rawPass = rawPass.replace("EnblMasterPasswd=", "");
                    if (rawPass.equals("1")) {
                        enableMaterPasswd = true;
                    } else {
                        enableMaterPasswd = false;
                    }
                }
                if (Pattern.matches("HashMasterPasswd=(.*?)", rawPass)) {
                    rawPass = rawPass.replace("HashMasterPasswd=", "");
                    if (rawPass.length() > 1) {
                        hashMasterPasswd = rawPass;
                    } else {
                        hashMasterPasswd = null;
                    }
                }
            }
        }
    }
}