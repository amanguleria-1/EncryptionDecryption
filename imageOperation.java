import javax.swing.*;
import java.awt.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

// Importing important libraries for encryption using AES
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class imageOperation {

    // Method to encrypt the file using AES
    public static void aesEncrypt(String key, File inputFile, File outputFile) throws Exception {
        System.out.println("Encrypting using AES...");
        SecretKey secretKey = new SecretKeySpec(key.getBytes(), "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        FileInputStream inputStream = new FileInputStream(inputFile);
        byte[] inputBytes = new byte[(int) inputFile.length()];
        inputStream.read(inputBytes);

        byte[] outputBytes = cipher.doFinal(inputBytes);

        FileOutputStream outputStream = new FileOutputStream(outputFile);
        outputStream.write(outputBytes);

        inputStream.close();
        outputStream.close();
    }

    // Method to decrypt the file using AES

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
    }

    // Method to Encrypt data using XOR operation
    public static void operate(int key, File file) {
        // file FileInputStream
        try {
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[fis.available()];
            fis.read(data);
            int i = 0;
            for (byte b : data) {
                System.out.print(b);
                data[i] = (byte) (b ^ key);
                i++;
            }

            FileOutputStream fos = new FileOutputStream(file);
            fos.write(data);
            fos.close();
            fis.close();
            JOptionPane.showMessageDialog(null, "Done");

        } catch (Exception e) {
            e.printStackTrace();
            JOptionPane.showMessageDialog(null, "An error occurred while processing the file.");
        }
    }

    public static void main(String[] args) {
        System.out.println("This is Testing");

        // Creating JFrame
        JFrame f = new JFrame(null, null);

        // Setting JFrame properties
        f.setTitle("File Encryption/Decryption");
        f.setSize(1100, 200);
        f.setLocationRelativeTo(null);

        f.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        f.setLayout(new FlowLayout());

        // Seting Font
        Font font = new Font("Roboto", Font.PLAIN, 25);

        JLabel instructionLabel = new JLabel("Choose a File and provide a key for encryption/decryption:");
        instructionLabel.setFont(font);
        f.add(instructionLabel);

        JTextField keyField = new JTextField(15);
        keyField.setFont(font); // Setting font family to text field
        f.add(keyField);

        // Combo box to choose between AES and XOR encryption/decryption
        String[] methods = { "XOR", "AES" };
        JComboBox<String> methodComboBox = new JComboBox<>(methods);
        methodComboBox.setFont(font);
        f.add(new JLabel("Select Method:"));
        f.add(methodComboBox);

        // Combo box to choose between encryption and decryption
        String[] operations = { "Encrypt", "Decrypt" };
        JComboBox<String> operationComboBox = new JComboBox<>(operations);
        operationComboBox.setFont(font);
        f.add(new JLabel("Select Operation:"));
        f.add(operationComboBox);

        JButton selectFileButton = new JButton(null, null);
        selectFileButton.setText("Select File");
        selectFileButton.setFont(font); // Setting font family to buttons
        f.add(selectFileButton);

        // Preview of the selected file
        JLabel selectedFileLabel = new JLabel("No file selected");
        selectedFileLabel.setFont(font);
        f.add(selectedFileLabel);

        JButton encryptButton = new JButton(null, null);
        encryptButton.setText("Encrypt/Decrypt");
        encryptButton.setFont(font); // Setting font family to buttons
        f.add(encryptButton);

        File[] selectedFile = new File[1]; // Using an array to store the file so it can be modified inside the lambda

        // Event listener for the select file button
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
                }

                else if (methodComboBox.getSelectedItem().equals("AES")) {
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
                }
            } else {
                JOptionPane.showMessageDialog(null, "Please select a file first.");
            }
        });

        f.setVisible(true);
    }
}
