import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Scanner;

public class SecureFileClient {

    private static final byte[] AES_KEY = hexToBytes("00112233445566778899AABBCCDDEEFF");

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Adresse IP du serveur: ");
        String host = scanner.nextLine();

        System.out.print("Port: ");
        int port = Integer.parseInt(scanner.nextLine());

        try (Socket socket = new Socket(host, port)) {
            socket.setTcpNoDelay(true);

            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            PrintWriter writer = new PrintWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8), false);

            // Authentification
            System.out.print("Login: ");
            String login = scanner.nextLine();
            System.out.print("Mot de passe: ");
            String password = scanner.nextLine();

            writer.println("LOGIN:" + login);
            writer.println("PASSWORD:" + password);
            writer.flush();
            out.flush();

            String authResp = reader.readLine();
            if (!"AUTH_OK".equals(authResp)) {
                System.err.println("Authentification echouee: " + authResp);
                return;
            }

            String sessionResp = reader.readLine();
            if (!"SESSION_READY".equals(sessionResp)) {
                System.err.println("Echec initialisation session");
                return;
            }

            System.out.println("Session active. Commandes: SEND_FILE, QUIT");

            while (true) {
                System.out.print(">> ");
                String cmd = scanner.nextLine().trim();

                if ("QUIT".equalsIgnoreCase(cmd)) {
                    writer.println("QUIT");
                    writer.flush();
                    out.flush();
                    String bye = reader.readLine();
                    if ("BYE".equals(bye)) {
                        System.out.println("Deconnexion reussie.");
                    }
                    break;
                }

                if ("SEND_FILE".equalsIgnoreCase(cmd)) {
                    writer.println("SEND_FILE");
                    writer.flush();
                    out.flush();

                    System.out.print("Chemin du fichier: ");
                    Path path = Path.of(scanner.nextLine());

                    if (!Files.isRegularFile(path)) {
                        System.err.println("Fichier introuvable: " + path);
                        continue;
                    }

                    long size = Files.size(path);
                    byte[] content = Files.readAllBytes(path);
                    String hash = sha256Hex(content);

                    writer.println("FILENAME:" + path.getFileName());
                    writer.println("FILESIZE:" + size);
                    writer.println("HASH:" + hash);
                    writer.println("END_META");
                    writer.flush();
                    out.flush();

                    String ready = reader.readLine();
                    if (!"READY".equals(ready)) {
                        System.err.println("Serveur non pret: " + ready);
                        continue;
                    }

                    // === Envoi chiffre (GCM) ===
                    SecretKeySpec keySpec = new SecretKeySpec(AES_KEY, "AES");
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

                    byte[] iv = new byte[12];
                    new SecureRandom().nextBytes(iv);
                    out.write(iv);
                    out.flush();

                    GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                    cipher.init(Cipher.ENCRYPT_MODE, keySpec, spec);

                    // Important : on ferme explicitement CipherOutputStream pour envoyer le tag GCM
                    try (FileInputStream fis = new FileInputStream(path.toFile());
                         CipherOutputStream cos = new CipherOutputStream(out, cipher)) {

                        byte[] buf = new byte[65536];
                        int n;
                        while ((n = fis.read(buf)) != -1) {
                            cos.write(buf, 0, n);
                        }
                        cos.flush();
                    }
                    out.flush(); // garantit que le tag est envoye

                    // === Lecture de la reponse ===
                    String response = reader.readLine();
                    if (response == null) {
                        System.err.println("Le serveur a ferme la connexion.");
                        break;
                    }

                    if ("OK".equals(response)) {
                        System.out.println("✅ Transfert reussi.");
                    } else {
                        System.err.println("❌ Echec: " + response);
                    }

                } else {
                    System.out.println("Commande inconnue. Utilisez SEND_FILE ou QUIT.");
                }
            }

        } catch (Exception e) {
            System.err.println("Erreur: " + e.getMessage());
            e.printStackTrace();
        } finally {
            scanner.close();
        }
    }

    private static String sha256Hex(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return bytesToHex(md.digest(data));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02X", b));
        return sb.toString();
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        if (len % 2 != 0) throw new IllegalArgumentException("Hex invalide");
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }
}