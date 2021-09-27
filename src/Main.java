import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.sql.*;
import java.util.Scanner;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {

    private static final String ALGO = "AES";
    private byte[] keyValue;

    public static void main(String args[]) {
        String user;
        String pass;
        String newUser;
        String newPass;

        try {
            Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/agenda", "root", "admin");

            File myObj = new File("C:\\Users\\Edy\\IdeaProjects\\Agenda\\Agenda.txt");
            FileWriter myWriter = new FileWriter("C:\\Users\\Edy\\IdeaProjects\\Agenda\\Agenda.txt", true);
            PrintWriter out = new PrintWriter(myWriter);

            Scanner scan = new Scanner(System.in);
            System.out.println("\nMENU\n");
            System.out.println("1. Login");
            System.out.println("2. Sing in");
            int if1 = scan.nextInt();

            if (if1 == 1){
                System.out.println("User: ");
                scan.nextLine();
                user = scan.nextLine();
                System.out.println("Password: ");
                pass = scan.nextLine();

                byte[] salt = null;
                String passBD = null;

                String query = "SELECT * FROM users WHERE user = '" + user + "'";
                try (Statement stmt = connection.createStatement()) {
                    ResultSet rs = stmt.executeQuery(query);
                    rs.next();
                    salt = rs.getBytes("salt");
                    passBD = rs.getString("password");
                } catch (SQLException e) {
                    System.out.println(e);
                }

                String password = getSecurePassword(pass, salt);

                if (!password.equals(passBD)) {
                    System.out.println("The password is wrong!");
                    return;
                }

                System.out.println("What do you want to do?");
                System.out.println("1. Write");
                System.out.println("2. Read");

                int if2 = scan.nextInt();

                if (if2 == 1) {
                    scan.nextLine();
                    String intData = scan.nextLine();
                    try {
                        Main aes = new Main("lv39eptlvuhaqqsr");
                        String encdata = aes.encrypt(intData);
                        out.println(encdata);

                    } catch (Exception ex) {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    out.close();
                } else if (if2 == 2) {
                    try {
                        Main aes = new Main("lv39eptlvuhaqqsr");

                        Scanner myReader = null;
                        try {
                            myReader = new Scanner(myObj);
                        } catch (FileNotFoundException e) {
                            e.printStackTrace();
                        }

                        String outData;

                        while (myReader.hasNextLine()) {
                            outData = myReader.nextLine();
                            String decdata = aes.decrypt(outData);
                            System.out.println(decdata);
                        }

                    } catch (Exception ex) {
                        Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }

            } else if (if1 == 2){
                System.out.print("User: ");
                scan.nextLine();
                newUser = scan.nextLine();

                System.out.println("\nPassword: ");
                newPass = scan.nextLine();

                String query2 = "SELECT * FROM users WHERE user = '" + newUser + "'";
                try (Statement stmt = connection.createStatement()) {
                    ResultSet rs = stmt.executeQuery(query2);
                    if (rs.next()) {
                        System.out.println("Error: The user already exists");
                        return;
                    }

                } catch (SQLException e) {
                    System.out.println(e);
                }

                byte[] newSalt = getSalt();

                String parola = getSecurePassword(newPass, newSalt);

                PreparedStatement stmt = connection.prepareStatement("INSERT INTO users (user, salt, password) VALUES (?, ?, ?)");

                stmt.setString(1, newUser);
                stmt.setBytes(2, newSalt);
                stmt.setString(3, parola);

                stmt.executeUpdate();

            }

        } catch (Exception e) {
            e.printStackTrace();
        }



    }

    public static String getSecurePassword(String password, byte[] salt) {

        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] bytes = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }

    private static byte[] getSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return salt;
    }

    public Main(String key) {
        keyValue = key.getBytes();
    }

    public String encrypt (String Data) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(Data.getBytes());
        String encryptedValue = java.util.Base64.getEncoder().encodeToString(encVal);
        return encryptedValue;
    }

    public String decrypt(String encryptedData) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance(ALGO);
        c.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedValue = java.util.Base64.getDecoder().decode(encryptedData);
        byte[] decValue = c.doFinal(decodedValue);
        String decryptedValue = new String(decValue);
        return decryptedValue;
    }

    private Key generateKey() throws Exception {
        Key key = new SecretKeySpec(keyValue, ALGO);
        return key;
    }
}
