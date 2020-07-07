package client;

import static client.Client.callOptionPane;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.swing.JOptionPane;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ClientHelp
{
    private static Object lock = new Object();
    public static byte[] encryptAsymetric(PublicKey publicKey, byte[] data)
    {
        Security.addProvider(new BouncyCastleProvider());
        try
        {
            Cipher cipher = Cipher.getInstance("RSA", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(data);
            return encryptedBytes;
        }
        catch (Exception e)
        {
            callOptionPane(null, "Error encrypting asimetrical" + "!", "Error!", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }
    public static void sendSymetric(byte[] data)
    {
        byte[] encData = null;
        encData = encryptSymetric(data, Client.sessionKey);
        Client.pw.println(encData.length); // u konekciju upise velicinu kriptovanog bloka 
        try
        {
            Client.br.readLine();// server je poslao OK ako je primio duzinu niza
            Client.os.write(encData); //upise podatke
        }
        catch (IOException e)
        {
            callOptionPane(null, "Error sending symetrical" + "!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
    }
    public static String reciveSymetric()
    {
        try
        {
            int len = Integer.parseInt(Client.br.readLine());
            byte[] result = null;
            Client.pw.println("OK");
            byte[] bytes = new byte[len];
            Client.is.read(bytes);
            result = ClientHelp.decryptSymetric(Client.alg, Client.sessionKey, bytes);
            return new String(result);
        }
        catch (Exception e)
        {
            callOptionPane(null, "Error reciving symetrical" + "!", "Error!", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }
    public static void reciveFile(String fajlZaPreuzimanje, String username)
    {
        String path = ".//resources/" + username + "/downloaded/" + fajlZaPreuzimanje;
        File file = new File(path);
        FileOutputStream fos = null;
        try
        {
            fos = new FileOutputStream(file);
        }
        catch (FileNotFoundException e1)
        {
            e1.printStackTrace();
        }
        int blocks = Integer.parseInt(new String(reciveSymetric())); // broj blokova
        byte[] niz = new byte[32256];
        sendSymetric("OK".getBytes());//OK
        for (int i = 0; i < blocks; i++)
        {
            niz = reciveSymetric().getBytes();
            try
            {
                fos.write(niz, 0, niz.length);
                fos.flush();
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
            sendSymetric("OK".getBytes());
        }
        try
        {
            fos.close();
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        if (reciveSymetric().equals("OK"))
        {
            callOptionPane(null, "File is downloaded" + "!", "Success!", JOptionPane.INFORMATION_MESSAGE);
        }
        else
        {
            callOptionPane(null, "File rejected" + "!", "Error!", JOptionPane.ERROR_MESSAGE);
            new File(path).delete();
        }
    }
    public static boolean sendFile(Scanner scan, boolean isNewFile, String path)
    {
        File fileForUpload = new File(path);
        if (fileForUpload.exists())
        {
            if (isNewFile)
            {
                sendSymetric(fileForUpload.getName().getBytes());//naziv fajla pretvori u bajtove
                reciveSymetric();
            }
            uploadFile(fileForUpload);
            return true;
        }
        else
        {
            callOptionPane(null, "File does not exist!", "Error!", JOptionPane.ERROR_MESSAGE);
            sendSymetric("NOK".getBytes());
            return false;
        }
    }
    private static byte[] encryptSymetric(byte[] data, SecretKey key)
    {
        Security.addProvider(new BouncyCastleProvider());
        byte[] encryptedData = null;
        try
        {
            Cipher c = Cipher.getInstance(Client.alg, "BC");
            c.init(Cipher.ENCRYPT_MODE, key);
            encryptedData = c.doFinal(data);
        }
        catch (InvalidKeyException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | NoSuchProviderException e)
        {
            callOptionPane(null, "Encription simetrical error!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
        return encryptedData;
    }
    private static byte[] decryptSymetric(String alg, SecretKey sesijskiKljuc, byte[] dataEnc)
    {
        Security.addProvider(new BouncyCastleProvider());
        Cipher c;
        try
        {
            c = Cipher.getInstance(alg, "BC");
            c.init(Cipher.DECRYPT_MODE, sesijskiKljuc);
            byte[] data = c.doFinal(dataEnc);
            return data;
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e)
        {
            callOptionPane(null, "Decription symetrical error!", "Error!", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }
    public static void end()
    {
        try
        {
            Client.br.close();
            Client.pw.close();
            Client.socket.close();
        }
        catch (IOException e)
        {
            callOptionPane(null, "Finalising failed!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
    }
    private static byte[] decryptAsymetric(byte[] encryptedData, String username)
    {
        PrivateKey key = getPrivateKey(username);
        Security.addProvider(new BouncyCastleProvider());
        Cipher cipher;
        try
        {
            cipher = Cipher.getInstance("RSA", "BC");
            cipher.init(Cipher.DECRYPT_MODE, key);//dekriptuje svojim privatnim jer je server kriptovao klijentovim javnim
            byte[] decryptedBytes = cipher.doFinal(encryptedData);
            return decryptedBytes;
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchProviderException e)
        {
            callOptionPane(null, "Decryption symetrical failed!", "Error!", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }
    private static PrivateKey getPrivateKey(String username)
    {
        File privKeyFile = new File(".//resources/" + username + "/" + username + "Key.der");
        Security.addProvider(new BouncyCastleProvider());
        DataInputStream dis;
        try
        {
            dis = new DataInputStream(new FileInputStream(privKeyFile));
            byte[] privKeyBytes = new byte[(int) privKeyFile.length()];
            dis.read(privKeyBytes);
            dis.close();
            KeyFactory keyFactory = null;
            keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
            return (PrivateKey) keyFactory.generatePrivate(privSpec);
        }
        catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException e1)
        {
            callOptionPane(null, "Key generation failed!", "Error!", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }
    private static void uploadFile(File fileForUpload)
    {
        BufferedInputStream bis = null;
        int count = (int) fileForUpload.length();
        int max_size = 32256;
        int blockNum = 1;
        byte[] buff = new byte[max_size];
        if (count > max_size)
        {
            blockNum = count / max_size;
            blockNum = (count % max_size == 0) ? blockNum : blockNum + 1;
        }
        sendSymetric(new Integer(blockNum).toString().getBytes());//slanje broja blokova
        reciveSymetric();//primi OK
        try
        {
            bis = new BufferedInputStream(new FileInputStream(fileForUpload));
            for (int i = 0; i < blockNum; i++)
            {
                int j = bis.read(buff);
                byte[] buffer = new byte[j];
                System.arraycopy(buff, 0, buffer, 0, j);
                sendSymetric(buffer);
                reciveSymetric();
            }
        }
        catch (IOException e1)
        {
            callOptionPane(null, "Server upload error!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
        try
        {
            bis.close();
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
    }
}
