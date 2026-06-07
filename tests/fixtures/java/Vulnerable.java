import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import javax.xml.parsers.*;

public class Vulnerable {
    // SQL Injection - Statement with string concatenation
    public void searchUser(String userId) throws Exception {
        java.sql.Connection conn = null;
        java.sql.Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE id=" + userId;
        java.sql.ResultSet rs = stmt.executeQuery(sql);
    }

    // Command Injection - Runtime.exec with user input
    public void pingHost(String host) throws Exception {
        Runtime rt = Runtime.getRuntime();
        String cmd = "ping -c 3 " + host;
        rt.exec(cmd);
    }

    // Path Traversal - File with user input
    public void readFile(String filename) throws Exception {
        File file = new File(filename);
        BufferedReader reader = new BufferedReader(new FileReader(file));
        String line = reader.readLine();
    }

    // XXE - DocumentBuilderFactory without secure configuration
    public void parseXml(String xmlInput) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        org.w3c.dom.Document doc = db.parse(new InputSource(new StringReader(xmlInput)));
    }

    // Insecure Deserialization - ObjectInputStream.readObject()
    public void deserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        Object obj = ois.readObject();
    }

    // Hardcoded credentials
    private static final String DB_PASSWORD = "super_secret_password_123";
    private static final String API_KEY = "sk-1234567890abcdef";
}
