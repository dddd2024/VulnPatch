import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

public class SimilarDownload {
    static class Request {
        String getParameter(String name) { return name; }
    }

    private final Path base = Paths.get("uploads").toAbsolutePath().normalize();

    public Path getAttachment(Request request) {
        String filename = request.getParameter("file");
        File target = new File(base.toFile(), filename); // VULNERABLE_PATH
        return target.toPath();
    }
}
