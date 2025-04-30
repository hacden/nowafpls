package org.example;

import burp.*;

import javax.swing.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Random;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class BurpExtender implements IBurpExtender, IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private IContextMenuInvocation context;
    private Random random = new Random();
    public PrintWriter stdout;
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stdout.println("===================================");
        this.stdout.println("hello nowafpls!");
        this.stdout.println("nowafpls loaded success!");
        this.stdout.println("===================================");
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName("nowafpls");
        callbacks.registerContextMenuFactory(this);
//        callbacks.registerHttpListener(this);
    }

    @Override
    public java.util.List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        this.context = invocation;
        ArrayList<JMenuItem> menuList = new ArrayList<>();

        if (invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST) {
            JMenuItem menuItem = new JMenuItem("Insert Junk Data Size");
            menuItem.addActionListener(e -> {
                try {
                    insertRandomData();
                } catch (IOException ex) {
                    throw new RuntimeException(ex);
                }
            });
            menuList.add(menuItem);
        }

        return menuList;
    }

    private String generateRandomString(int length, String charset) {
        if (charset == null) {
            charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(charset.charAt(random.nextInt(charset.length())));
        }
        return sb.toString();
    }

    private String generateRandomParam() {
        String[] prefixes = {"id", "user", "session", "token", "auth", "request", "data", "temp", "cache", "author"};
        String prefix = prefixes[random.nextInt(prefixes.length)];
        String suffix = generateRandomString(random.nextInt(5) + 4, null);
        return prefix + "_" + suffix;
    }

    private String generateVariedContent(int size) {
        StringBuilder content = new StringBuilder();
        int remainingSize = size;

        while (remainingSize > 0) {
            int chunkSize = Math.min(random.nextInt(25) + 8, remainingSize);
            int chunkType = random.nextInt(4) + 1;

            String chunk;
            switch (chunkType) {
                case 1:
                    chunk = generateRandomString(chunkSize, null);
                    break;
                case 2:
                    chunk = generateRandomString(chunkSize, "0123456789ABCDEF");
                    break;
                case 3:
                    chunk = generateRandomString(chunkSize, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/");
                    break;
                default:
                    chunk = generateRandomString(chunkSize, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~");
            }

            content.append(chunk);
            remainingSize -= chunkSize;
        }

        return content.toString();
    }

    private void insertRandomData() throws IOException {
        IHttpRequestResponse message = context.getSelectedMessages()[0];
        byte[] request = message.getRequest();
        int[] selectionBounds = context.getSelectionBounds();
        int insertionPoint = selectionBounds != null ? selectionBounds[0] : request.length;

        JPanel optionsPanel = new JPanel();
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.Y_AXIS));

        String[] sizes = {"8 KB", "16 KB", "32 KB", "64 KB", "128 KB", "1024 KB", "Custom"};
        JComboBox<String> dropdown = new JComboBox<>(sizes);
        JTextField customSizeField = new JTextField(10);
        JLabel customSizeLabel = new JLabel("Custom size (bytes):");

        customSizeField.setVisible(false);
        customSizeLabel.setVisible(false);

        optionsPanel.add(dropdown);
        optionsPanel.add(customSizeLabel);
        optionsPanel.add(customSizeField);

        dropdown.addActionListener(e -> {
            boolean isCustomSelected = dropdown.getSelectedItem().equals("Custom");
            customSizeLabel.setVisible(isCustomSelected);
            customSizeField.setVisible(isCustomSelected);
            if (isCustomSelected) {
                customSizeField.requestFocus();
            }
            SwingUtilities.getWindowAncestor(optionsPanel).pack();
        });

        int dialog = JOptionPane.showConfirmDialog(null, optionsPanel,
                "Select Junk Data Size", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);

        if (dialog == JOptionPane.OK_OPTION) {
            int sizeBytes;
            String selectedSize = (String) dropdown.getSelectedItem();

            if (selectedSize.equals("Custom")) {
                try {
                    sizeBytes = Integer.parseInt(customSizeField.getText());
                } catch (NumberFormatException ex) {
                    JOptionPane.showMessageDialog(null, "Please enter a valid number for custom size.");
                    return;
                }
            } else {
                sizeBytes = Integer.parseInt(selectedSize.split(" ")[0]) * 1024;
            }

            byte contentType = helpers.analyzeRequest(message).getContentType();
            String junkData;

            if (contentType == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
                String paramName = generateRandomParam();
                junkData = paramName + "=" + generateVariedContent(sizeBytes - paramName.length() - 1) + "&";
            } else if (contentType == IRequestInfo.CONTENT_TYPE_XML) {
                String commentContent = generateVariedContent(sizeBytes - 7);
                junkData = "<!--" + commentContent + "-->";
            } else if (contentType == IRequestInfo.CONTENT_TYPE_JSON) {
                String paramName = generateRandomParam();
                junkData = "\"" + paramName + "\":\"" +
                        generateVariedContent(sizeBytes - paramName.length() - 5) + "\",";
            } else if (contentType == IRequestInfo.CONTENT_TYPE_MULTIPART) {
                junkData = createMultipartJunk(request, sizeBytes);
            } else {
                return;
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            baos.write(request, 0, insertionPoint);
            baos.write(junkData.getBytes());
            baos.write(request, insertionPoint, request.length - insertionPoint);
            message.setRequest(baos.toByteArray());
        }
    }

    private String createMultipartJunk(byte[] request, int size) {
        String requestString = helpers.bytesToString(request);
        Pattern pattern = Pattern.compile("boundary=([\\w-]+)");
        Matcher matcher = pattern.matcher(requestString);

        if (!matcher.find()) {
            return "";
        }

        String boundary = matcher.group(1);
        String junkFieldName = generateRandomParam();

        String multipartStructure = String.format(
                "--%s\r\n" +
                        "Content-Disposition: form-data; name=\"%s\"\r\n\r\n" +
                        "%s\r\n",
                boundary, junkFieldName, ""
        );

        int structureSize = multipartStructure.length();
        String junkData = generateVariedContent(size - structureSize);

        return String.format(multipartStructure, boundary, junkFieldName, junkData);
    }

}