
// Importing libraries to create GUI
import javax.swing.*;
import java.awt.*;

// Importing libraries to handle files
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

// Importing important libraries for encryption using AES
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

// Importing library to fetch uniqueID for each ecrpyted file 
import java.util.UUID;

// Importing Library for performing hashing
import java.security.MessageDigest;

// Importing libraries for database connectivity
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class encryptDecrypt {
    private static String originalFileHash;
    private static String encryptedFileHash;

    public static void aesEncrypt(String key, File inputFile, File outputFile) throws Exception {
        System.out.println("Encrypting using AES...");

        // Read the original content of the file
        byte[] inputBytes = Files.readAllBytes(inputFile.toPath());

        // Generate a hash of the original content
        originalFileHash = getSHA256Hash(inputBytes);
        System.out.println("Hash of the original file: " + originalFileHash);

        // Encrypt the file
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] outputBytes = cipher.doFinal(inputBytes);

        // Save the encrypted content to the file
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        outputStream.write(outputBytes);
        outputStream.close();

        String uniqueID = generateUniqueID();
        System.out.println("Unique ID for this encryption: " + uniqueID);

        // Save encrypted data, hash, and unique ID to the database
        saveToDatabase(uniqueID, outputBytes, originalFileHash);

        System.out.println("File Encrypted Successfully");
    }

    public static void aesDecrypt(String key, File inputFile, File outputFile) throws Exception {
        System.out.println("Decrypting using AES...");

        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        FileInputStream inputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int) inputFile.length()];
        inputStream.read(inputBytes);

        byte[] outputBytes = cipher.doFinal(inputBytes);

        FileOutputStream outputStream = new FileOutputStream(outputFile);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();

        // Check authenticity after decryption
        System.out.println("Checking authenticity after decryption...");
        checkAuthenticityBeforeAndAfter(establishConnection());

        System.out.println("Hash of the decrypted file: " + originalFileHash);

        System.out.println("Decryption completed.");
    }

    public static String getUniqueIDFromFileName(String fileName) {
        // Assuming the file name is in the format: "uniqueID_filename"
        String[] parts = fileName.split("_");
        return parts.length > 0 ? parts[0] : null;
    }

    public static String getHashValueFromDatabase(String uniqueID) {

        try (Connection connection = establishConnection()) {
            if (connection != null) {
                String sql = "SELECT hash_value FROM encrypted_files WHERE unique_id = ?";
                try (PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
                    preparedStatement.setString(1, uniqueID);
                    try (var resultSet = preparedStatement.executeQuery()) {
                        if (resultSet.next()) {
                            return resultSet.getString("hash_value");
                        }
                    }
                }
            } else {
                System.err.println("Failed to establish a database connection");
            }
        } catch (SQLException e) {
            System.err.println("Error retrieving hash value from the database: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    public static List<String> getFileIDsFromDatabase(Connection connection) {
        List<String> fileIDs = new ArrayList<>();

        try {
            String sql = "SELECT unique_id FROM encrypted_files";
            try (PreparedStatement preparedStatement = connection.prepareStatement(sql);
                    ResultSet resultSet = preparedStatement.executeQuery()) {

                while (resultSet.next()) {
                    fileIDs.add(resultSet.getString("unique_id"));
                }
            }
        } catch (Exception e) {
            System.err.println("Error retrieving file IDs from the database: " + e.getMessage());
            e.printStackTrace();
        }

        return fileIDs;
    }

    private static void checkAuthenticityBeforeAndAfter(Connection connection) {
        System.out.println("Checking authenticity for files");

        // Retrieve the list of encrypted files from the database
        List<String> fileIDs = getFileIDsFromDatabase(connection);

        // Iterate through each file and perform authenticity check
        for (String fileID : fileIDs) {
            try {
                // Retrieve original hash value from the database
                String originalHash = getHashValueFromDatabase(fileID);

                // Perform decryption
                File encryptedFile = new File(fileID + "_filename");
                File decryptedFile = new File(fileID + "_decrypted_filename");
                aesDecrypt("your_aes_key", encryptedFile, decryptedFile);

                // Calculate hash of the decrypted file
                String decryptedFileHash = getSHA256Hash(Files.readAllBytes(decryptedFile.toPath()));

                // Compare the calculated hash with the original hash
                if (decryptedFileHash.equals(originalHash)) {
                    System.out.println("File with ID " + fileID + " is authentic.");
                } else {
                    System.out.println("File with ID " + fileID + " is not authentic. Possible tampering.");
                }
            } catch (Exception e) {
                System.err.println("Decrypting...");
            }
        }
    }

    public static void saveToDatabase(String uniqueID, byte[] encryptedData, String hashValue) {
        try (Connection connection = establishConnection()) {
            if (connection != null) {
                String sql = "INSERT INTO encrypted_files (unique_id, encrypted_content, hash_value) VALUES (?, ?, ?)";
                try (PreparedStatement preparedStatement = connection.prepareStatement(sql)) {
                    preparedStatement.setString(1, uniqueID);
                    preparedStatement.setBytes(2, encryptedData);
                    preparedStatement.setString(3, hashValue);
                    preparedStatement.executeUpdate();
                    System.out.println("Data saved to database successfully");
                }
            } else {
                System.err.println("Failed to establish a database connection");
            }
        } catch (SQLException e) {
            System.err.println("Error saving encrypted data to the database: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void operate(int key, File file) {
        try {
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[fis.available()];
            fis.read(data);

            // Perform XOR operation on the content of the file with the key
            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) (data[i] ^ key);
            }

            // Write the XOR-encrypted data back to the original file
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(data);
            fos.close();
            fis.close();

            String uniqueID = generateUniqueID();
            encryptedFileHash = getSHA256Hash(data);
            System.out.println("Hash of the encrypted file: " + encryptedFileHash);
            System.out.println("Unique ID for this encryption: " + uniqueID);
            JOptionPane.showMessageDialog(null, "Done");

        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(null, "An error occurred while processing the file.");
        }
    }

    public static void caesarEncrypt(int key, File file) {
        try {
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[fis.available()];
            fis.read(data);

            for (int i = 0; i < data.length; i++) {
                data[i] = (byte) ((data[i] + key) % 256);
            }

            FileOutputStream fos = new FileOutputStream(file);
            fos.write(data);
            fos.close();
            fis.close();

            String uniqueID = generateUniqueID();
            encryptedFileHash = getSHA256Hash(data);
            System.out.println("Hash of the encrypted file: " + encryptedFileHash);
            System.out.println("Unique ID for this encryption: " + uniqueID);
            JOptionPane.showMessageDialog(null, "Done");

        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(null, "An error occurred while processing the file.");
        }
    }

    public static void caesarDecrypt(int key, File file) {
        caesarEncrypt(256 - key, file);
    }

    public static String generateUniqueID() {
        return UUID.randomUUID().toString();
    }

    public static String getSHA256Hash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data);
        StringBuffer hexString = new StringBuffer();

        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if (hex.length() == 1)
                hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
    }

    public static Connection establishConnection() throws SQLException {
        // JDBC URL, username, and password of your database
        String url = "jdbc:mysql://localhost:3306/file_hider?useUnicode=true&characterEncoding=UTF-8";
        String user = "root";
        String password = "root1234";

        // Load the JDBC driver
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            System.err.println("JDBC driver not found");
            e.printStackTrace();
            return null;
        }

        // Establish a connection
        return DriverManager.getConnection(url, user, password);
    }

    public static void main(String[] args) {
        System.out.println("This is Testing");

        // Establish a database connection
        try (Connection connection = establishConnection()) {
            if (connection != null) {
                System.out.println("Connected to the database");

                // Your existing code for GUI and encryption/decryption methods
                // ...
            } else {
                System.err.println("Failed to establish a database connection");
            }
        } catch (SQLException e) {
            System.err.println("Database connection failed");
            e.printStackTrace();
        }

        JFrame f = new JFrame(null, null);
        f.setTitle("File Encryption/Decryption");
        f.setSize(1100, 200);
        f.setLocationRelativeTo(null);
        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        f.setLayout(new FlowLayout());

        Font font = new Font("Roboto", Font.PLAIN, 25);

        JLabel instructionLabel = new JLabel("Choose a File and provide a key for encryption/decryption:");
        instructionLabel.setFont(font);
        f.add(instructionLabel);

        JTextField keyField = new JTextField(15);
        keyField.setFont(font);
        f.add(keyField);

        String[] methods = { "XOR", "AES", "Caesar" };
        JComboBox<String> methodComboBox = new JComboBox<>(methods);
        methodComboBox.setFont(font);
        f.add(new JLabel("Select Method:"));
        f.add(methodComboBox);

        String[] operations = { "Encrypt", "Decrypt" };
        JComboBox<String> operationComboBox = new JComboBox<>(operations);
        operationComboBox.setFont(font);
        f.add(new JLabel("Select Operation:"));
        f.add(operationComboBox);

        JButton selectFileButton = new JButton(null, null);
        selectFileButton.setText("Select File");
        selectFileButton.setFont(font);
        f.add(selectFileButton);

        JLabel selectedFileLabel = new JLabel("No file selected");
        selectedFileLabel.setFont(font);
        f.add(selectedFileLabel);

        JButton encryptButton = new JButton(null, null);
        encryptButton.setText("Encrypt/Decrypt");
        encryptButton.setFont(font);
        f.add(encryptButton);

        File[] selectedFile = new File[1];

        selectFileButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            int returnVal = fileChooser.showOpenDialog(f);
            if (returnVal == JFileChooser.APPROVE_OPTION) {
                selectedFile[0] = fileChooser.getSelectedFile();
                selectedFileLabel.setText("Selected File: " + selectedFile[0].getName());
            }
        });

        encryptButton.addActionListener(e -> {
            if (selectedFile[0] != null) {
                String text = keyField.getText();
                if (methodComboBox.getSelectedItem().equals("XOR")) {
                    try {
                        int temp = Integer.parseInt(text);
                        operate(temp, selectedFile[0]);
                    } catch (NumberFormatException ex) {
                        JOptionPane.showMessageDialog(null, "For XOR, please provide a valid integer key.");
                    }
                } else if (methodComboBox.getSelectedItem().equals("AES")) {
                    try {
                        if (text.length() != 16 && text.length() != 24 && text.length() != 32) {
                            throw new Exception("AES key must be 16, 24, or 32 characters long.");
                        }
                        if (operationComboBox.getSelectedItem().equals("Encrypt")) {
                            aesEncrypt(text, selectedFile[0], selectedFile[0]);
                        } else if (operationComboBox.getSelectedItem().equals("Decrypt")) {
                            aesDecrypt(text, selectedFile[0], selectedFile[0]);
                        }
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(null, "AES Error: " + ex.getMessage());
                    }
                } else if (methodComboBox.getSelectedItem().equals("Caesar")) {
                    try {
                        int temp = Integer.parseInt(text);
                        if (operationComboBox.getSelectedItem().equals("Encrypt")) {
                            caesarEncrypt(temp, selectedFile[0]);
                        } else if (operationComboBox.getSelectedItem().equals("Decrypt")) {
                            caesarDecrypt(256 - temp, selectedFile[0]);
                        }
                    } catch (NumberFormatException ex) {
                        JOptionPane.showMessageDialog(null, "For Caesar Cipher, please provide a valid integer key.");
                    }
                }
            } else {
                JOptionPane.showMessageDialog(null, "Please select a file first.");
            }
        }

        );

        f.setVisible(true);
    }
}