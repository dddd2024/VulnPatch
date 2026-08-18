import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class VulnerableDownload {
    static class Request {
        String getParameter(String name) { return name; }
    }

    private final Path base = Paths.get("files").toAbsolutePath().normalize();

    public Path download(Request request) {
        String filename = request.getParameter("filename");
        File target = new File(base.toFile(), filename); // VULNERABLE_PATH
        return target.toPath();
    }
}
