import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class SimpleSql {
    public ResultSet findUser(Connection conn, String userId) throws Exception {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE id=" + userId; // VULNERABLE_SQL
        return stmt.executeQuery(sql);
    }
}
