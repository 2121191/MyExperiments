package com.myrsa.demo;

import com.myrsa.demo.rsa.RSAKeyPair;
import com.myrsa.demo.rsa.RSA;
import javafx.fxml.FXML;
import javafx.scene.control.*;
import javafx.scene.control.Alert.AlertType;
import javafx.scene.layout.VBox;
import javafx.stage.FileChooser;
import javafx.scene.control.TextInputDialog; // 导入 TextInputDialog
import javafx.util.Pair; // 导入 Pair

import java.io.*;
import java.math.BigInteger;
import java.util.Base64;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.util.Optional; // 导入 Optional

public class RSAController {

    // --- UI 控件 ---
    @FXML private ComboBox<String> keySizeComboBox;
    @FXML private Button generateKeyButton;
    @FXML private TextArea publicKeyText;
    @FXML private TextArea privateKeyText;
    @FXML private Button savePublicKeyButton;
    @FXML private Button loadPublicKeyButton;
    @FXML private Button savePrivateKeyButton;
    @FXML private Button loadPrivateKeyButton;

    @FXML private TextArea inputText;
    @FXML private Button encryptButton;
    @FXML private Button decryptButton;
    @FXML private TextArea outputText;

    @FXML private TextArea messageForSignVerifyText;

    // Signature/Verification specific controls
    @FXML private Button hashMessageButton;
    @FXML private TextArea messageHashText;
    @FXML private Button signButton;
    @FXML private TextArea signatureInputText;
    @FXML private Button verifyButton;
    @FXML private TextArea verificationResultText;

    // --- Section VBoxes and ToggleGroup ---
    @FXML private VBox keyManagementSection;
    @FXML private VBox encryptionDecryptionSection;
    @FXML private VBox signingVerificationSection;
    @FXML private ToggleButton keyManagementNavButton;
    @FXML private ToggleButton encryptionDecryptionNavButton;
    @FXML private ToggleButton signingVerificationNavButton;
    @FXML private ToggleGroup navigationGroup;

    private RSAKeyPair currentKeyPair; // 当前生成的或加载的密钥对

    @FXML
    public void initialize() {
        keySizeComboBox.getItems().addAll("512", "1024", "2048");
        keySizeComboBox.getSelectionModel().selectFirst(); // 默认选择 512 位

        // 密钥管理按钮
        generateKeyButton.setOnAction(event -> handleGenerateKey());
        savePublicKeyButton.setOnAction(event -> handleSaveKey(true));
        loadPublicKeyButton.setOnAction(event -> handleLoadKey(true));
        savePrivateKeyButton.setOnAction(event -> handleSaveKey(false));
        loadPrivateKeyButton.setOnAction(event -> handleLoadKey(false));

        // 加密解密按钮
        encryptButton.setOnAction(event -> handleEncrypt());
        decryptButton.setOnAction(event -> handleDecrypt());

        // 签名验证按钮
        hashMessageButton.setOnAction(event -> handleHashMessage());
        signButton.setOnAction(event -> handleSign());
        verifyButton.setOnAction(event -> handleVerify());

        // 初始化导航栏
        navigationGroup = new ToggleGroup();
        keyManagementNavButton.setToggleGroup(navigationGroup);
        encryptionDecryptionNavButton.setToggleGroup(navigationGroup);
        signingVerificationNavButton.setToggleGroup(navigationGroup);

        // 添加监听器，根据选择显示不同功能区
        navigationGroup.selectedToggleProperty().addListener((observable, oldValue, newValue) -> {
            if (newValue == keyManagementNavButton) {
                showSection("keyManagement");
            } else if (newValue == encryptionDecryptionNavButton) {
                showSection("encryptionDecryption");
            } else if (newValue == signingVerificationNavButton) {
                showSection("signingVerification");
            }
        });

        // 默认显示密钥管理区
        keyManagementNavButton.setSelected(true);
        updateKeyDisplay();
    }

    // 导航处理（已通过监听器实现）
    @FXML
    public void handleNavigation() {
    }

    private void showSection(String sectionId) {
        keyManagementSection.setVisible(false);
        keyManagementSection.setManaged(false);
        encryptionDecryptionSection.setVisible(false);
        encryptionDecryptionSection.setManaged(false);
        signingVerificationSection.setVisible(false);
        signingVerificationSection.setManaged(false);

        switch (sectionId) {
            case "keyManagement":
                keyManagementSection.setVisible(true);
                keyManagementSection.setManaged(true);
                break;
            case "encryptionDecryption":
                encryptionDecryptionSection.setVisible(true);
                encryptionDecryptionSection.setManaged(true);
                break;
            case "signingVerification":
                signingVerificationSection.setVisible(true);
                signingVerificationSection.setManaged(true);
                break;
        }
    }

    // --- 密钥管理 ---
    private void handleGenerateKey() {
        try {
            int keySize = Integer.parseInt(keySizeComboBox.getSelectionModel().getSelectedItem());
            currentKeyPair = RSA.generateKeyPair(keySize);
            updateKeyDisplay();
            showAlert(AlertType.INFORMATION, "密钥生成成功", "已生成 " + keySize + " 位的 RSA 密钥对。");
        } catch (NumberFormatException e) {
            showAlert(AlertType.ERROR, "错误", "请选择有效的密钥大小。");
        } catch (IllegalArgumentException e) {
            showAlert(AlertType.ERROR, "生成密钥失败", e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            showAlert(AlertType.ERROR, "生成密钥失败", "生成密钥时发生错误: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void handleSaveKey(boolean isPublic) {
        if (currentKeyPair == null) {
            showAlert(AlertType.WARNING, "保存失败", "请先生成或加载密钥对。");
            return;
        }

        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("保存" + (isPublic ? "公钥" : "私钥"));
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("RSA Key Pair Files", "*.key"));

        File file = fileChooser.showSaveDialog(generateKeyButton.getScene().getWindow());
        if (file != null) {
            try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(file))) {
                if (isPublic) {
                    // Only save e and n for public key
                    oos.writeObject(new RSAKeyPair(currentKeyPair.getPublicKeyExponent(), null, currentKeyPair.getModulus()));
                } else {
                    // Save d and n for private key (or full key pair)
                    oos.writeObject(currentKeyPair); // Saving the whole object, but for private key use, only d and n are needed.
                }
                showAlert(AlertType.INFORMATION, "保存成功", (isPublic ? "公钥" : "私钥") + "已保存到 " + file.getAbsolutePath());
            } catch (IOException e) {
                showAlert(AlertType.ERROR, "保存失败", "保存密钥时发生错误: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private void handleLoadKey(boolean isPublic) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("加载" + (isPublic ? "公钥" : "私钥"));
        fileChooser.getExtensionFilters().add(new FileChooser.ExtensionFilter("RSA Key Pair Files", "*.key"));

        File file = fileChooser.showOpenDialog(generateKeyButton.getScene().getWindow());
        if (file != null) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
                RSAKeyPair loadedKeyPair = (RSAKeyPair) ois.readObject();

                // 合并加载的密钥到 currentKeyPair
                if (currentKeyPair == null) {
                    currentKeyPair = new RSAKeyPair(null, null, null); // 初始化
                }

                if (isPublic) {
                    currentKeyPair = new RSAKeyPair(loadedKeyPair.getPublicKeyExponent(), currentKeyPair.getPrivateKeyExponent(), loadedKeyPair.getModulus());
                } else {
                    currentKeyPair = new RSAKeyPair(currentKeyPair.getPublicKeyExponent(), loadedKeyPair.getPrivateKeyExponent(), loadedKeyPair.getModulus());
                }

                updateKeyDisplay();
                showAlert(AlertType.INFORMATION, "加载成功", (isPublic ? "公钥" : "私钥") + "已从 " + file.getAbsolutePath() + " 加载。");

            } catch (IOException | ClassNotFoundException e) {
                showAlert(AlertType.ERROR, "加载失败", "加载密钥时发生错误: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private void updateKeyDisplay() {
        if (currentKeyPair != null) {
            publicKeyText.setText(currentKeyPair.getPublicKeyString());
            privateKeyText.setText(currentKeyPair.getPrivateKeyString());
        } else {
            publicKeyText.setText("未生成/加载公钥");
            privateKeyText.setText("未生成/加载私钥");
        }
    }

    // --- 加密解密 ---
    private void handleEncrypt() {
        String plaintext = inputText.getText();
        if (plaintext.isEmpty()) {
            showAlert(AlertType.WARNING, "输入为空", "请输入要加密的明文。");
            return;
        }

        // 弹窗让用户输入公钥指数和模数
        Optional<Pair<String, String>> result = showKeyInputDialog("输入公钥参数进行加密", "公钥 (e):", "模数 (n):");

        result.ifPresent(keys -> {
            try {
                BigInteger publicKeyExponent = new BigInteger(keys.getKey());
                BigInteger modulus = new BigInteger(keys.getValue());

                String encryptedText = RSA.encrypt(plaintext, publicKeyExponent, modulus);
                outputText.setText(encryptedText);
                // 简化成功提示
                showAlert(AlertType.INFORMATION, "加密结果", "加密成功！");
            } catch (NumberFormatException e) {
                // 简化失败提示
                showAlert(AlertType.ERROR, "加密结果", "加密失败！输入的密钥参数格式不正确。");
                e.printStackTrace();
            } catch (IllegalArgumentException e) {
                showAlert(AlertType.ERROR, "加密结果", "加密失败！" + e.getMessage()); // 保持原有的具体错误信息
                e.printStackTrace();
            } catch (Exception e) {
                // 简化失败提示
                showAlert(AlertType.ERROR, "加密结果", "加密失败！");
                e.printStackTrace();
            }
        });
    }

    private void handleDecrypt() {
        String ciphertextBase64 = inputText.getText();
        if (ciphertextBase64.isEmpty()) {
            showAlert(AlertType.WARNING, "输入为空", "请输入要解密的密文。");
            return;
        }

        // 弹窗让用户输入私钥指数和模数
        Optional<Pair<String, String>> result = showKeyInputDialog("输入私钥参数进行解密", "私钥 (d):", "模数 (n):");

        result.ifPresent(keys -> {
            try {
                BigInteger privateKeyExponent = new BigInteger(keys.getKey());
                BigInteger modulus = new BigInteger(keys.getValue());

                String decryptedText = RSA.decrypt(ciphertextBase64, privateKeyExponent, modulus);
                outputText.setText(decryptedText);
                // 移除解密成功后的弹窗
                // showAlert(AlertType.INFORMATION, "解密结果", "解密成功！");
            } catch (NumberFormatException e) {
                // 简化失败提示
                showAlert(AlertType.ERROR, "解密结果", "解密失败！输入的密钥参数格式不正确。");
                e.printStackTrace();
            } catch (IllegalArgumentException e) {
                showAlert(AlertType.ERROR, "解密结果", "解密失败！" + e.getMessage()); // 保持原有的具体错误信息
                e.printStackTrace();
            } catch (Exception e) {
                // 简化失败提示
                showAlert(AlertType.ERROR, "解密结果", "解密失败！");
                e.printStackTrace();
            }
        });
    }

    // --- 数字签名与验证 ---
    private void handleHashMessage() {
        String message = messageForSignVerifyText.getText();
        if (message.isEmpty()) {
            showAlert(AlertType.WARNING, "输入为空", "请输入要计算哈希的消息。");
            return;
        }
        try {
            String hashBase64 = RSA.hashMessageToBase64(message);
            messageHashText.setText(hashBase64);
            showAlert(AlertType.INFORMATION, "哈希计算成功", "消息的 SHA-256 哈希值已计算。");
        } catch (NoSuchAlgorithmException e) {
            showAlert(AlertType.ERROR, "哈希失败", "不支持的哈希算法 (SHA-256)。");
            e.printStackTrace();
        } catch (Exception e) {
            showAlert(AlertType.ERROR, "哈希失败", "计算哈希过程中发生错误: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void handleSign() {
        String message = messageForSignVerifyText.getText();
        if (message.isEmpty()) {
            showAlert(AlertType.WARNING, "输入为空", "请输入要签名的消息。");
            return;
        }

        // 弹窗让用户输入私钥指数和模数
        Optional<Pair<String, String>> result = showKeyInputDialog("输入私钥参数进行签名", "私钥指数 (d):", "模数 (n):");

        result.ifPresent(keys -> {
            try {
                BigInteger privateKeyExponent = new BigInteger(keys.getKey());
                BigInteger modulus = new BigInteger(keys.getValue());

                String signature = RSA.sign(message, privateKeyExponent, modulus);
                signatureInputText.setText(signature);
                showAlert(AlertType.INFORMATION, "签名成功", "消息已使用用户提供的私钥参数签名。");
            } catch (NumberFormatException e) {
                showAlert(AlertType.ERROR, "签名失败", "输入的密钥参数格式不正确，请确保为有效的数字。");
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                showAlert(AlertType.ERROR, "签名失败", "不支持的哈希算法 (SHA-256)。");
                e.printStackTrace();
            } catch (Exception e) {
                showAlert(AlertType.ERROR, "签名失败", "签名过程中发生错误: " + e.getMessage());
                e.printStackTrace();
            }
        });
    }

    private void handleVerify() {
        String message = messageForSignVerifyText.getText();
        String signatureBase64 = signatureInputText.getText();

        if (message.isEmpty() || signatureBase64.isEmpty()) {
            showAlert(AlertType.WARNING, "输入为空", "请输入原始消息和签名数据。");
            return;
        }

        // 弹窗让用户输入公钥指数和模数
        Optional<Pair<String, String>> result = showKeyInputDialog("输入公钥参数进行验签", "公钥指数 (e):", "模数 (n):");

        result.ifPresent(keys -> {
            try {
                BigInteger publicKeyExponent = new BigInteger(keys.getKey());
                BigInteger modulus = new BigInteger(keys.getValue());

                boolean isValid = RSA.verify(message, signatureBase64, publicKeyExponent, modulus);

                // 只显示从签名恢复的哈希值
                byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
                BigInteger s = new BigInteger(1, signatureBytes);
                BigInteger decryptedHashBigInt = s.modPow(publicKeyExponent, modulus); // 计算 H'
                String decryptedHashBase64ForDisplay = Base64.getEncoder().encodeToString(decryptedHashBigInt.toByteArray());

                verificationResultText.setText(decryptedHashBase64ForDisplay); // 只显示恢复的哈希值

                // 简化成功/失败提示
                if (isValid) {
                    showAlert(AlertType.INFORMATION, "验签结果", "验签成功！");
                } else {
                    showAlert(AlertType.WARNING, "验签结果", "验签失败！");
                }
            } catch (NumberFormatException e) {
                showAlert(AlertType.ERROR, "验签结果", "验签失败！输入的密钥参数格式不正确。");
                verificationResultText.setText("错误: 参数格式不正确");
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                showAlert(AlertType.ERROR, "验签结果", "验签失败！不支持的哈希算法。");
                verificationResultText.setText("错误: 不支持的哈希算法");
                e.printStackTrace();
            } catch (IllegalArgumentException e) {
                showAlert(AlertType.ERROR, "验签结果", "验签失败！无效的签名数据。");
                verificationResultText.setText("错误: 无效签名或格式");
                e.printStackTrace();
            } catch (Exception e) {
                showAlert(AlertType.ERROR, "验签结果", "验签失败！");
                verificationResultText.setText("错误: 验签过程失败");
                e.printStackTrace();
            }
        });
    }

    // --- 辅助方法 ---

    /**
     * 显示一个包含两个文本输入框的弹窗，用于输入密钥参数。
     * @param title 弹窗标题
     * @param label1 第一个输入框的标签
     * @param label2 第二个输入框的标签
     * @return 返回一个 Optional<Pair<String, String>>，如果用户点击确定，则包含两个输入框的值；否则为空。
     */
    private Optional<Pair<String, String>> showKeyInputDialog(String title, String label1, String label2) {
        Dialog<Pair<String, String>> dialog = new Dialog<>();
        dialog.setTitle(title);
        dialog.setHeaderText("请输入密钥参数");

        // 设置按钮类型
        ButtonType okButtonType = new ButtonType("确定", ButtonBar.ButtonData.OK_DONE);
        dialog.getDialogPane().getButtonTypes().addAll(okButtonType, ButtonType.CANCEL);

        // 创建两个 TextField
        TextField textField1 = new TextField();
        textField1.setPromptText(label1);
        TextField textField2 = new TextField();
        textField2.setPromptText(label2);

        // 创建布局
        VBox content = new VBox(10); // 10像素间距
        content.getChildren().addAll(new Label(label1), textField1, new Label(label2), textField2);

        dialog.getDialogPane().setContent(content);

        // 请求焦点
        javafx.application.Platform.runLater(() -> textField1.requestFocus());

        // 将结果转换成 Pair<String, String>
        dialog.setResultConverter(dialogButton -> {
            if (dialogButton == okButtonType) {
                return new Pair<>(textField1.getText(), textField2.getText());
            }
            return null;
        });

        return dialog.showAndWait();
    }


    private void showAlert(AlertType type, String title, String message) {
        Alert alert = new Alert(type);
        alert.setTitle(title);
        alert.setHeaderText(null); // No header
        alert.setContentText(message);
        alert.showAndWait();
    }
}