import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;

public class SecureFileServer {

    private static final byte[] AES_KEY = hexToBytes("00112233445566778899AABBCCDDEEFF");

    private static final Map<String, String> USER_STORE = new HashMap<>();
    static {
        USER_STORE.put("Oumayma", "01012004");
        USER_STORE.put("Fatima", "29102003");
        USER_STORE.put("admin", "admin");
    }

    public static void main(String[] args) {
        int port = 9090;
        String storageDir = "received";

        if (args.length >= 1) port = Integer.parseInt(args[0]);
        if (args.length >= 2) storageDir = args[1];

        new File(storageDir).mkdirs();
        System.out.println("Serveur demarre sur port " + port + " | Repertoire: " + storageDir);

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            while (true) {
                Socket socket = serverSocket.accept();
                socket.setTcpNoDelay(true);
                System.out.println("Connexion acceptee: " + socket.getRemoteSocketAddress());
                new Thread(new ClientSession(socket, storageDir)).start();
            }
        } catch (IOException e) {
            System.err.println("Erreur serveur: " + e.getMessage());
        }
    }

    private static class ClientSession implements Runnable {
        private final Socket socket;
        private final String storageDir;

        ClientSession(Socket socket, String storageDir) {
            this.socket = socket;
            this.storageDir = storageDir;
        }

        @Override
        public void run() {
            InputStream rawIn = null;
            OutputStream out = null;
            BufferedReader reader = null;
            PrintWriter writer = null;

            try {
                rawIn = socket.getInputStream();
                out = socket.getOutputStream();
                reader = new BufferedReader(new InputStreamReader(rawIn, StandardCharsets.UTF_8));
                writer = new PrintWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8), false);

                // Authentification (une seule fois)
                if (!performAuthentication(reader, writer)) {
                    return;
                }

                writer.println("SESSION_READY");
                writer.flush();

                // Boucle de traitement des commandes
                while (true) {
                    String command = reader.readLine();
                    if (command == null) {
                        break; // client deconnecte
                    }

                    if ("QUIT".equals(command)) {
                        writer.println("BYE");
                        writer.flush();
                        break;
                    } else if ("SEND_FILE".equals(command)) {
                        processFileTransfer(reader, writer, rawIn, out);
                    } else {
                        writer.println("UNKNOWN_COMMAND");
                        writer.flush();
                    }
                }

            } catch (Exception e) {
                if (!socket.isClosed()) {
                    System.err.println("Erreur dans la session: " + e.getMessage());
                }
            } finally {
                closeQuietly(writer, out, reader, rawIn, socket);
            }
        }

        private boolean performAuthentication(BufferedReader reader, PrintWriter writer) throws IOException {
            String loginLine = reader.readLine();
            String passLine = reader.readLine();

            if (loginLine == null || !loginLine.startsWith("LOGIN:") ||
                    passLine == null || !passLine.startsWith("PASSWORD:")) {
                writer.println("AUTH_FAIL");
                writer.flush();
                return false;
            }

            String login = loginLine.substring(6).trim();
            String password = passLine.substring(9).trim();

            if (!USER_STORE.getOrDefault(login, "").equals(password)) {
                writer.println("AUTH_FAIL");
                writer.flush();
                return false;
            }

            writer.println("AUTH_OK");
            writer.flush();
            return true;
        }

        private void processFileTransfer(BufferedReader reader, PrintWriter writer,
                                         InputStream rawIn, OutputStream out) {
            try {
                String filename = null;
                long fileSize = -1;
                String hash = null;

                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("FILENAME:")) filename = line.substring(9).trim();
                    else if (line.startsWith("FILESIZE:")) fileSize = Long.parseLong(line.substring(9).trim());
                    else if (line.startsWith("HASH:")) hash = line.substring(5).trim();
                    else if ("END_META".equals(line)) break;
                }

                if (filename == null || fileSize < 0 || hash == null) {
                    writer.println("PROTO_ERROR");
                    writer.flush();
                    return;
                }

                writer.println("READY");
                writer.flush();

                // Lecture de l'IV (12 octets)
                byte[] iv = new byte[12];
                int total = 0;
                while (total < 12) {
                    int n = rawIn.read(iv, total, 12 - total);
                    if (n == -1) throw new IOException("Connexion fermee");
                    total += n;
                }

                // Dechiffrement
                SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, "AES");
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                cipher.init(Cipher.DECRYPT_MODE, keySpec, spec);

                CipherInputStream cis = new CipherInputStream(rawIn, cipher);

                Path outputPath = Path.of(storageDir, sanitizeFileName(filename));
                byte[] buffer = new byte[65536];
                long totalRead = 0;
                MessageDigest md = MessageDigest.getInstance("SHA-256");

                try (FileOutputStream fos = new FileOutputStream(outputPath.toFile())) {
                    int n;
                    while ((n = cis.read(buffer)) != -1) {
                        fos.write(buffer, 0, n);
                        md.update(buffer, 0, n);
                        totalRead += n;
                    }
                }

                // Verification
                if (totalRead != fileSize) {
                    Files.deleteIfExists(outputPath);
                    writer.println("SIZE_MISMATCH");
                    writer.flush();
                    return;
                }

                String computedHash = bytesToHex(md.digest());
                if (!computedHash.equalsIgnoreCase(hash)) {
                    Files.deleteIfExists(outputPath);
                    writer.println("HASH_MISMATCH");
                    writer.flush();
                    return;
                }

                writer.println("OK");
                writer.flush();
                out.flush();

                System.out.println("Fichier recu: " + outputPath + " (" + totalRead + " octets)");

            } catch (Exception e) {
                System.err.println("Echec du transfert: " + e.getMessage());
                try {
                    writer.println("ERROR");
                    writer.flush();
                } catch (Exception ignored) {
                }
            }
        }

        private static String sanitizeFileName(String name) {
            String clean = name.replaceAll("[^a-zA-Z0-9.-]", "");
            return clean.length() > 200 ? clean.substring(0, 200) : clean;
        }

        private static void closeQuietly(Closeable... resources) {
            for (Closeable r : resources) {
                if (r != null) {
                    try { r.close(); } catch (IOException ignored) {}
                }
            }
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Hex invalide");
        }
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}