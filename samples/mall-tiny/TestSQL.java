import java.sql.*;

public class TestSQL {
    public void queryUser(Connection conn, String userId) throws SQLException {
        Statement stmt = conn.createStatement();
        String sql = "SELECT * FROM users WHERE id=" + userId;
        ResultSet rs = stmt.executeQuery(sql);
    }
}
