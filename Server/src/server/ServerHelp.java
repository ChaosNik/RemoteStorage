package server;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import static server.ServerThread.callOptionPane;

public class ServerHelp
{
    private static X509Certificate ca = ServerThread.getX509Cert(".//ca/cacert.cer");
    private static X509CRL crl = ServerThread.getCrl(".//ca/crl/crl.pem");
    public static byte[] decryptAsymetric(byte[] data)
    {
        Security.addProvider(new BouncyCastleProvider());
        PrivateKey privateKey = getPrivateKey();
        byte[] decryptedBytes = null;
        try
        {
            Cipher cipher = Cipher.getInstance("RSA", "BC");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            decryptedBytes = cipher.doFinal(data);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e)
        {
            callOptionPane(null, "Decryption asymetrical error!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
        return decryptedBytes;
    }
    public static PrivateKey getPrivateKey()
    {
        File privKeyFile = new File(".//ca/caKey.der");
        Security.addProvider(new BouncyCastleProvider());
        DataInputStream dis;
        try
        {
            dis = new DataInputStream(new FileInputStream(privKeyFile));
            byte[] privKeyBytes = new byte[(int) privKeyFile.length()];
            dis.read(privKeyBytes);
            dis.close();
            KeyFactory keyFactory = null;
            keyFactory = KeyFactory.getInstance("RSA", "BC");
            PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
            return (PrivateKey) keyFactory.generatePrivate(privSpec);
        }
        catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e1)
        {
            callOptionPane(null, "Unable to generate keys from file!", "Error!", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }
    public static boolean checkLogin(String username, String password)
    {//sa common name iz certifikata
        String hashPass;
        try
        {
            hashPass = ServerThread.getHashPass(username, password);
            String tmp = ServerThread.passMap.get(username);
            if (hashPass.equals(tmp))
            {
                return true;
            }
            else
            {
                return false;
            }
        }
        catch (NoSuchProviderException | NoSuchAlgorithmException e)
        {
            callOptionPane(null, "Loggin failed!", "Error!", JOptionPane.ERROR_MESSAGE);
            return false;
        }
    }
    public static void sendSymetric(byte[] data)
    {
        byte[] encData = null;
        encData = encryptSymetric(ServerThread.alg, ServerThread.sessionKey, data);
        ServerThread.pw.println(encData.length); // u konekciju upise velicinu kriptovanog bloka 
        try
        {
            ServerThread.br.readLine();// klijent je poslao OK ako je primio duzinu niza
            ServerThread.os.write(encData); //upise podatke
        }
        catch (IOException e)
        {
            callOptionPane(null, "Error sending symetrical!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
    }
    public static Date getDate()
    {
        Date datumRez = null;
        try
        {
            datumRez = new SimpleDateFormat("yyyy.MM.dd 'at' HH:mm:ss").parse(new SimpleDateFormat("yyyy.MM.dd 'at' HH:mm:ss").format(Calendar.getInstance().getTime()));
        }
        catch (ParseException e)
        {
            e.printStackTrace();
        }
        return datumRez;
    }
    public static String getCommonName(X509Certificate cert)
    {
        String distinguishedName = cert.getSubjectDN().toString();
        int begin = distinguishedName.indexOf("=");
        int end = distinguishedName.indexOf(',');
        return (distinguishedName.substring(++begin, end)).toString();
    }
    public static byte[] decryptSymetric(byte[] dataEnc)
    {
        Security.addProvider(new BouncyCastleProvider());
        try
        {
            Cipher c = Cipher.getInstance(ServerThread.alg, "BC");
            c.init(Cipher.DECRYPT_MODE, ServerThread.sessionKey);
            byte[] data = c.doFinal(dataEnc);
            return data;
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e)
        {
            callOptionPane(null, "Error decrypting symetrical!", "Error!", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }
    public static String reciveSymetric()
    {
        try
        {
            int len = Integer.parseInt(ServerThread.br.readLine());
            byte[] result = null;
            ServerThread.pw.println("OK");
            byte[] bytes = new byte[len];
            ServerThread.is.read(bytes);
            result = ServerHelp.decryptSymetric(bytes);
            return new String(result);
        }
        catch (Exception e)
        {
            callOptionPane(null, "Error reciving symetrical!", "Error!", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }
    public static void sendFile(File file)
    {
        Security.addProvider(new BouncyCastleProvider());
        byte[] dataEncoded = null;
        byte[] cryptedByte = new byte[512];
        byte[] procitaniDigitalniPotpis = new byte[512];
        try
        {
            FileInputStream fis = new FileInputStream(file);
            MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
            Cipher aCipher = Cipher.getInstance("RSA", "BC");
            aCipher.init(Cipher.DECRYPT_MODE, ServerThread.caCert.getPublicKey());
            fis.read(cryptedByte);
            procitaniDigitalniPotpis = aCipher.doFinal(cryptedByte);
            //username
            fis.read(cryptedByte);
            dataEncoded = aCipher.doFinal(cryptedByte);
            md.update(dataEncoded);
            //file name
            fis.read(cryptedByte);
            dataEncoded = aCipher.doFinal(cryptedByte);
            md.update(dataEncoded);
            //sesijski kljuc
            fis.read(cryptedByte);
            dataEncoded = aCipher.doFinal(cryptedByte);
            md.update(dataEncoded);
            SecretKey sessionKey = new SecretKeySpec(dataEncoded, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, sessionKey);
            int count = (int) file.length() - 2048;
            int max_size = 32256 + 16;
            int blocks = 1;
            if (count > max_size)
            {
                blocks = count / max_size;
                blocks = (count % max_size == 0) ? blocks : blocks + 1;
            }
            sendSymetric(String.valueOf(blocks).getBytes());//slanje broja blokova
            reciveSymetric();//klijent poslao OK
            for (int i = 0; i < blocks; i++)
            {
                byte[] buff = new byte[max_size];
                int j = fis.read(buff);
                byte[] buffer = cipher.doFinal(buff, 0, j);
                sendSymetric(buffer);//posalje blok 
                md.update(buffer);
                reciveSymetric();//ok
            }
            byte[] generisaniPotpis = md.digest();
            fis.close();
            if (Arrays.equals(procitaniDigitalniPotpis, generisaniPotpis))
            {
                callOptionPane(null, "Signature is OK!", "Error!", JOptionPane.INFORMATION_MESSAGE);
                sendSymetric("OK".getBytes());
            }
            else
            {
                callOptionPane(null, "Signature error!", "Error!", JOptionPane.ERROR_MESSAGE);
                sendSymetric("Fajl je odbacen!".getBytes());
            }
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | NoSuchPaddingException | IOException | IllegalBlockSizeException | BadPaddingException e)
        {
            e.printStackTrace();
        }
    }
    public static void reciveFile(String fileName, String username, X509Certificate userCert)
    {
        Security.addProvider(new BouncyCastleProvider());
        String path = ".//resources/files/" + username + "/" + fileName;
        File file = new File(path);
        byte[] textBytes = null;
        byte[] cryptedByte = new byte[512];
        FileOutputStream fos = null;
        RandomAccessFile raf = null;
        try
        {
            fos = new FileOutputStream(file);
        }
        catch (FileNotFoundException e1)
        {
            callOptionPane(null, "File not found!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
        KeyGenerator keyGenerator;
        try
        {
            //kljuc
            keyGenerator = KeyGenerator.getInstance("AES", "BC");
            keyGenerator.init(128);
            SecretKey sKey = keyGenerator.generateKey();
            // simetricna enkripcija
            Cipher cipherSymmetrically = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
            cipherSymmetrically.init(Cipher.ENCRYPT_MODE, sKey);
            Cipher cipherSignature = Cipher.getInstance("RSA", "BC");
            cipherSignature.init(Cipher.ENCRYPT_MODE, ServerHelp.getPrivateKey());//potpis se radi privatnim, a provjerava javnim
            MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
            md.reset();
            // potpis
            fos.write(new byte[512]);
            // username
            textBytes = username.getBytes();
            md.update(textBytes);
            cryptedByte = cipherSignature.doFinal(textBytes);
            fos.write(cryptedByte);
            // ime fajla
            textBytes = ServerThread.namesMap.get(fileName).getBytes();
            md.update(textBytes);
            cryptedByte = cipherSignature.doFinal(textBytes);
            fos.write(cryptedByte);
            // sesijski kljuc
            textBytes = sKey.getEncoded();
            md.update(textBytes);
            cryptedByte = cipherSignature.doFinal(textBytes);
            fos.write(cryptedByte);
            // primi broj blokova
            int blockNum = Integer.parseInt(new String(reciveSymetric()));
            sendSymetric("OK".getBytes());
            int max_size = 32256;
            byte[] buff = new byte[max_size];
            for (int i = 0; i < blockNum; i++)
            {
                buff = reciveSymetric().getBytes();
                md.update(buff, 0, buff.length);
                fos.write(cipherSymmetrically.doFinal(buff, 0, buff.length));
                fos.flush();
                sendSymetric("OK".getBytes());
            }
            fos.close();
            byte[] hashFingerprint = md.digest();
            cryptedByte = cipherSignature.doFinal(hashFingerprint);
            raf = new RandomAccessFile(path, "rw");
            raf.write(cryptedByte, 0, 512);
            raf.close();
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IOException | IllegalBlockSizeException | BadPaddingException e1)
        {
            callOptionPane(null, "Error with something!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
    }
    public static boolean checkCertificate(X509Certificate userCert, String username)
    {
        if (!username.equals(getCommonName(userCert)))
        {
            return false;
        }
        try
        {
            userCert.checkValidity(getDate());
        }
        catch (CertificateExpiredException | CertificateNotYetValidException e)
        {
            return false;
        }
        if (!verify(userCert))
        {
            return false;
        }
        if (isRevoked(userCert))
        {
            return false;
        }
        return true;
    }
    public static ArrayList<Change> getLogsForFile(String username, String fileName) throws IOException
    {
        ArrayList<Change> rezultat = new ArrayList<Change>();
        for (Change i : ServerThread.changes)
        {
            if (i.getUsername().equals(username) && i.getFileName().equals(fileName))
            {
                rezultat.add(i);
            }
        }
        return rezultat;
    }
    public static String getHashedFileName(String username, String file)
    {
        MessageDigest digest;
        try
        {
            digest = MessageDigest.getInstance("SHA-256");
            digest.reset();
            digest.update(username.getBytes());
            byte[] hashedBytes = digest.digest(file.getBytes());
            String encoded = Base64.getEncoder().encodeToString(hashedBytes);
            return encoded;
        }
        catch (NoSuchAlgorithmException e)
        {
            callOptionPane(null, "No such algorithm!", "Error!", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }
    private static byte[] encryptSymetric(String alg, SecretKey sessionKey, byte[] data)
    {
        Security.addProvider(new BouncyCastleProvider());
        byte[] encryptedData = null;
        try
        {
            Cipher c = Cipher.getInstance(alg, "BC");
            c.init(Cipher.ENCRYPT_MODE, sessionKey);
            encryptedData = c.doFinal(data);
        }
        catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e)
        {
            callOptionPane(null, "Error encrypting simetrical!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
        return encryptedData;
    }
    private static boolean isRevoked(X509Certificate userCert)
    {
        X509CRLEntry pom = null;
        pom = crl.getRevokedCertificate(userCert);
        if (pom != null)
        {
            callOptionPane(null, "Certificate is in crl!", "Error!", JOptionPane.ERROR_MESSAGE);
            Date datumPovlacenja = pom.getRevocationDate();
            if (getDate().after(datumPovlacenja))
            {
                callOptionPane(null, "Date after revokation date!", "Error!", JOptionPane.ERROR_MESSAGE);
                return true;
            }
        }
        return false;
    }
    private static boolean verify(X509Certificate userCert)
    {
        try
        {
            userCert.verify(ca.getPublicKey());
        }
        catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e)
        {
            callOptionPane(null, "Failed verification!", "Error!", JOptionPane.ERROR_MESSAGE);
            return false;
        }
        return true;
    }
    private static byte[] encryptAsymetric(PublicKey publicKey, byte[] data)
    {
        Security.addProvider(new BouncyCastleProvider());
        try
        {
            Cipher cipher = Cipher.getInstance("RSA", "BC");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = cipher.doFinal(data);
            return encryptedBytes;
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchProviderException e)
        {
            callOptionPane(null, "Error encrypting asimetrical!", "Error!", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }
    private static SecretKey generateKey128bit()
    {
        Security.addProvider(new BouncyCastleProvider());
        try
        {
            KeyGenerator keyGen;
            keyGen = KeyGenerator.getInstance("AES", "BC");
            keyGen.init(128);
            SecretKey sessionKey = keyGen.generateKey();
            return sessionKey;
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException e)
        {
            callOptionPane(null, "Error generating session 128!", "Error!", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }
}
