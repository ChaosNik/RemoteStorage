package server;

import java.awt.Component;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ServerThread extends Thread
{
    public static String caPath = ".//ca/cacert.cer";
    public static String alg = "AES/ECB/PKCS5Padding";// simetricni
    public static String hashMapsPath = ".//resources/maps/";
    public static String logFilePath = ".//resources/logs.hash";
    public static HashMap<String, byte[]> saltMap = new HashMap<>();//username,salt
    public static HashMap<String, String> passMap;//pass, hash
    public static HashMap<String, String> namesMap = new HashMap<String, String>();//hash, fileNAme
    public static ArrayList<Change> changes = new ArrayList<Change>();
    public static SecretKey sessionKey;
    int sessionId;
    private Socket clientSocket;
    public static BufferedReader br;
    public static PrintWriter pw;
    public static InputStream is;
    public static OutputStream os;
    public X509Certificate userCert = null;
    public static X509Certificate caCert = null;
    private static CertificateFactory cf;
    //Static values
    static
    {
        try
        {
            try
            {
                cf = CertificateFactory.getInstance("X.509");
                caCert = (X509Certificate) cf.generateCertificate(new FileInputStream(caPath));
            }
            catch (CertificateException e)
            {
                callOptionPane(null, "Error generating certificates" + "!", "Error!", JOptionPane.ERROR_MESSAGE);
            }
            init();
            loadChangesList();
        }
        catch (ClassNotFoundException | NoSuchAlgorithmException | NoSuchProviderException | IOException e)
        {
            callOptionPane(null, "Error running init methode!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
    }
    public ServerThread(Socket socket, int i) throws IOException
    {
        sessionId = i;
        clientSocket = socket;
        br = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        pw = new PrintWriter(new OutputStreamWriter(clientSocket.getOutputStream()), true);
        is = clientSocket.getInputStream();
        os = clientSocket.getOutputStream();
        start();
    }
    public void run()
    {
        String action = null, responce = null;
        try
        {
            try
            {
                Cipher.getInstance(alg);
            }
            catch (Exception e)
            {
                callOptionPane(null, "Error instantiating client socket!", "Error!", JOptionPane.ERROR_MESSAGE);
                end();
                return;
            }
            byte[] symetricalCrypted = new byte[512];
            is.read(symetricalCrypted);
            try
            {
                sessionKey = new SecretKeySpec(ServerHelp.decryptAsymetric(symetricalCrypted), "AES");
            }
            catch (Exception e)
            {
                pw.println("Session key initialisation error!");
                end();
                return;
            }
            pw.println("Session key success!");
            pw.flush();
            //preuzimanje username#password
            boolean logged = false;
            String username = "", password = "";
            byte[] pom = new byte[2 * 1024 * 1024];
            while (!logged)
            {
                try
                {
                    int len = Integer.parseInt(br.readLine());//preuzima duzinu niza podataka
                    pw.println("OK");
                    pom = new byte[len];
                    is.read(pom);//procita podatke
                    //TREBA DEKRIPTOVATI SIMETRICNO DA SE OD SIFRATA DOBIJE USERNAME#PASSWORD
                    String str = new String(ServerHelp.decryptSymetric(pom));
                    username = str.split("#")[0];
                    password = str.split("#")[1];
                    logged = ServerHelp.checkLogin(username, password);
                }
                catch (Exception e)
                {
                    callOptionPane(null, "Error sending login!", "Error!", JOptionPane.ERROR_MESSAGE);
                    end();
                    return;
                }
                byte[] content = (logged) ? "OK".getBytes() : "NOK".getBytes();
                ServerHelp.sendSymetric(content);
                if (logged)
                {
                    int len = Integer.parseInt(br.readLine());
                    pw.println("OK");
                    byte[] certBytesCrypted = new byte[len];
                    is.read(certBytesCrypted);
                    byte[] certBytes;
                    certBytes = ServerHelp.decryptSymetric(certBytesCrypted);
                    try
                    {
                        userCert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
                    }
                    catch (CertificateException e)
                    {
                        callOptionPane(null, "Error generating certificate!", "Error!", JOptionPane.ERROR_MESSAGE);
                    }
                    if (!ServerHelp.checkCertificate(userCert, username))
                    {
                        callOptionPane(null, "Users cert not checked!", "Error!", JOptionPane.ERROR_MESSAGE);
                        pw.println("Validation failed!");
                        pw.flush();
                    }
                    else
                    {
                        callOptionPane(null, "Users cert checked!", "Success!", JOptionPane.INFORMATION_MESSAGE);
                        pw.println("Validation success!");
                        pw.flush();
                    }
                }
            }
            boolean exit = false;
            while (!exit)
            {
                try
                {
                    action = ServerHelp.reciveSymetric();
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }
                if (action.equals("1"))
                {//izlistavanje svih fajlova
                    File dir = new File(".//resources/files/" + username);
                    File[] listaFajlova = dir.listFiles();
                    if (listaFajlova.length == 0)
                    {
                        responce = "No files on server!";
                        ServerHelp.sendSymetric(responce.getBytes());
                    }
                    else
                    {
                        responce = "";
                        String[] realNames = new String[listaFajlova.length];
                        for (int i = 0; i < listaFajlova.length; i++)
                        {
                            String hashedName = listaFajlova[i].getName();
                            String realName = namesMap.get(hashedName);
                            realNames[i] = realName;
                            responce += (i + 1) + " : " + realName + System.lineSeparator();
                        }
                        ServerHelp.sendSymetric(responce.getBytes());//slanje spiska fajlova
                        action = new String(ServerHelp.reciveSymetric());//prijem indeksa fajla
                        int index;
                        index = Integer.parseInt(action);
                        if (index < 1 || index > listaFajlova.length)
                        {
                            ServerHelp.sendSymetric("Wrong file choise!".getBytes());
                        }
                        else
                        {
                            ServerHelp.sendSymetric("Choose file action!.".getBytes());
                            action = new String(ServerHelp.reciveSymetric());//prijem podopcije
                            if (action.equals("1"))
                            {//download za klijenta
                                ServerHelp.sendSymetric(realNames[index - 1].getBytes());//slanje naziva fajla
                                ServerHelp.reciveSymetric();//sko je sve uredu klijent je poslao OK
                                ServerHelp.sendFile(listaFajlova[index - 1]);
                            }
                            else if (action.equals("2"))
                            {//izmjena
                                ServerHelp.sendSymetric("OK".getBytes());
                                try
                                {
                                    changes.add(new Change(username, realNames[index - 1], new SimpleDateFormat("yyyy.MM.dd 'at' HH:mm:ss").format(Calendar.getInstance().getTime())));
                                    ServerHelp.reciveFile(listaFajlova[index - 1].getName(), username, userCert);
                                }
                                catch (Exception e)
                                {
                                    e.printStackTrace();
                                }
                            }
                            else if (action.equals("3"))
                            {//pregled spiska promjena
                                ArrayList<Change> logs = ServerHelp.getLogsForFile(username, realNames[index - 1]);
                                if (logs.size() > 0)
                                {
                                    responce = "";
                                    for (Change log : logs)
                                    {
                                        responce += log.getDate() + System.lineSeparator();
                                    }
                                    ServerHelp.sendSymetric(responce.getBytes());
                                }
                                else
                                {
                                    ServerHelp.sendSymetric("File has no changes.".getBytes());
                                }
                            }
                        }
                    }
                }
                else if (action.equals("2"))
                {//upload
                    ServerHelp.sendSymetric("OK".getBytes());
                    String file = ServerHelp.reciveSymetric();//primi naziv fajla
                    if (!file.equals("NOK"))
                    {
                        ServerHelp.sendSymetric("OK".getBytes());
                        Random r = new Random();
                        int tmp = r.nextInt(20000) + 10000;
                        String fileNameHashed = String.valueOf(tmp);
                        try
                        {
                            namesMap.put(fileNameHashed, file);
                            ServerHelp.reciveFile(fileNameHashed, username, userCert);
                            callOptionPane(null, "File uploaded!", "Error!", JOptionPane.INFORMATION_MESSAGE);
                        }
                        catch (Exception e)
                        {
                            e.printStackTrace();
                        }
                    }
                }
                else if (action.equals("3"))
                {
                    saveMaps();
                    saveListLogs();
                    exit = true;
                }
            }
            end();
        }
        catch (IOException ex)
        {
            ex.printStackTrace();
        }
    }
    public static String getHashPass(String username, String pass) throws NoSuchAlgorithmException, NoSuchProviderException
    {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.reset();
        byte[] tmp = saltMap.get(username);
        if (tmp == null)
        {
            return new String("");
        }
        else
        {
            md.update(tmp);//dodamo salt 
            return Base64.getEncoder().encodeToString(md.digest(pass.getBytes()));
        }
    }
    public static X509Certificate getX509Cert(String certPath)
    {
        X509Certificate cert = null;
        BufferedInputStream bis1;
        if (new File(certPath).exists())
        {
            try
            {
                bis1 = new BufferedInputStream(new FileInputStream(new File(certPath)));
                cert = (X509Certificate) cf.generateCertificate(bis1);
            }
            catch (FileNotFoundException | CertificateException e)
            {
                callOptionPane(null, "X509 generation failed!", "Error!", JOptionPane.ERROR_MESSAGE);
            }
        }
        return cert;
    }
    public static X509CRL getCrl(String string)
    {
        X509CRL crl = null;
        try
        {
            crl = (X509CRL) cf.generateCRL(new FileInputStream(string));
        }
        catch (CRLException | FileNotFoundException e)
        {
            callOptionPane(null, "Error reading crl!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
        return crl;
    }
    private static void loadChangesList()
    {
        Security.addProvider(new BouncyCastleProvider());
        File logs = new File(logFilePath);
        ;
        byte[] dataEncoded = null;
        byte[] cryptedByte = new byte[512];
        byte[] procitaniDigitalniPotpis = new byte[512];
        try
        {
            FileInputStream fis = new FileInputStream(logs);
            MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
            md.reset();
            Cipher aCipher;
            aCipher = Cipher.getInstance("RSA", "BC");
            aCipher.init(Cipher.DECRYPT_MODE, ServerThread.caCert.getPublicKey());
            fis.read(cryptedByte);
            procitaniDigitalniPotpis = aCipher.doFinal(cryptedByte);
            //sesijski kljuc
            fis.read(cryptedByte);
            dataEncoded = aCipher.doFinal(cryptedByte);
            md.update(dataEncoded);
            SecretKey sessionKey = new SecretKeySpec(dataEncoded, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
            cipher.init(Cipher.DECRYPT_MODE, sessionKey);
            int len = (int) logs.length() - 1024;
            byte[] data = new byte[len];
            int j = fis.read(data);
            byte[] buffer = cipher.doFinal(data, 0, j);
            md.update(buffer);
            ByteArrayInputStream in = new ByteArrayInputStream(buffer);
            ObjectInputStream is = new ObjectInputStream(in);
            changes = (ArrayList<Change>) is.readObject();
            in.close();
            is.close();
            fis.close();
            byte[] generisaniPotpis = md.digest();
            if (!Arrays.equals(procitaniDigitalniPotpis, generisaniPotpis))
            {
                callOptionPane(null, "Salt signature error!", "Error!", JOptionPane.ERROR_MESSAGE);
                throw new Exception("Error");
            }
        }
        catch (Exception e)
        {
            callOptionPane(null, "Changes list signature error!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
    }
    private void saveListLogs()
    {
        Security.addProvider(new BouncyCastleProvider());
        File logs = new File(logFilePath);
        try
        {
            FileOutputStream fos1 = new FileOutputStream(logs);
            // generisemo kljuc
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
            keyGenerator.init(128);
            SecretKey key = keyGenerator.generateKey();
            Cipher cipherSymmetrically;
            byte[] textBytes = null;
            byte[] cryptedByte = new byte[512];
            cipherSymmetrically = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
            cipherSymmetrically.init(Cipher.ENCRYPT_MODE, key);
            Cipher cipherSignature = Cipher.getInstance("RSA", "BC");
            cipherSignature.init(Cipher.ENCRYPT_MODE, ServerHelp.getPrivateKey());
            MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
            md.reset();
            fos1.write(new byte[512]);
            // sesijski kljuc
            textBytes = key.getEncoded();
            md.update(textBytes);
            cryptedByte = cipherSignature.doFinal(textBytes);
            fos1.write(cryptedByte);
            // upisemo logList
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ObjectOutputStream os = new ObjectOutputStream(out);
            os.writeObject(changes);
            byte[] array = out.toByteArray();
            md.update(array, 0, array.length);
            fos1.write(cipherSymmetrically.doFinal(array, 0, array.length));
            fos1.flush();
            fos1.close();
            byte[] hesOtisak = md.digest();
            cryptedByte = cipherSignature.doFinal(hesOtisak);
            RandomAccessFile raf1 = new RandomAccessFile(logFilePath, "rw");
            raf1.write(cryptedByte, 0, 512);
            raf1.close();
            out.close();
            os.close();
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | IllegalBlockSizeException | BadPaddingException | IOException | NoSuchPaddingException | InvalidKeyException e)
        {
            callOptionPane(null, "Saving changes list failed!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
    }
    private void saveMaps()
    {
        Security.addProvider(new BouncyCastleProvider());
        File salt = new File(hashMapsPath + "salt.hash");
        File pass = new File(hashMapsPath + "pass.hash");
        File names = new File(hashMapsPath + "names.hash");
        try
        {
            FileOutputStream fos1 = new FileOutputStream(salt);
            FileOutputStream fos2 = new FileOutputStream(pass);
            FileOutputStream fos3 = new FileOutputStream(names);
            //generisemo kljuc
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BC");
            keyGenerator.init(128);
            SecretKey key = keyGenerator.generateKey();
            Cipher cipherSymmetrically;
            byte[] textBytes = null;
            byte[] cryptedByte = new byte[512];
            cipherSymmetrically = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
            cipherSymmetrically.init(Cipher.ENCRYPT_MODE, key);
            Cipher cipherSignature = Cipher.getInstance("RSA", "BC");
            cipherSignature.init(Cipher.ENCRYPT_MODE, ServerHelp.getPrivateKey());//potpis se radi privatnim, a provjerava javnim
            MessageDigest md1 = MessageDigest.getInstance("SHA-256", "BC");
            md1.reset();
            MessageDigest md2 = MessageDigest.getInstance("SHA-256", "BC");
            md1.reset();
            MessageDigest md3 = MessageDigest.getInstance("SHA-256", "BC");
            md1.reset();
            fos1.write(new byte[512]);
            fos2.write(new byte[512]);
            fos3.write(new byte[512]);
            // sesijski kljuc
            textBytes = key.getEncoded();
            md1.update(textBytes);
            md2.update(textBytes);
            md3.update(textBytes);
            cryptedByte = cipherSignature.doFinal(textBytes);
            fos1.write(cryptedByte);
            fos2.write(cryptedByte);
            fos3.write(cryptedByte);
            //upisemo saltMap
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ObjectOutputStream os = new ObjectOutputStream(out);
            os.writeObject(saltMap);
            byte[] array = out.toByteArray();
            md1.update(array, 0, array.length);
            fos1.write(cipherSymmetrically.doFinal(array, 0, array.length));
            fos1.flush();
            fos1.close();
            byte[] hesOtisak = md1.digest();
            cryptedByte = cipherSignature.doFinal(hesOtisak);
            RandomAccessFile raf1 = new RandomAccessFile(hashMapsPath + "salt.hash", "rw");
            raf1.write(cryptedByte, 0, 512);
            raf1.close();
            out.close();
            os.close();
            //upisemo passMap
            ByteArrayOutputStream out1 = new ByteArrayOutputStream();
            ObjectOutputStream os1 = new ObjectOutputStream(out1);
            os1.writeObject(passMap);
            byte[] array1 = out1.toByteArray();
            md2.update(array1, 0, array1.length);
            fos2.write(cipherSymmetrically.doFinal(array1, 0, array1.length));
            fos2.flush();
            fos2.close();
            byte[] hesOtisak1 = md2.digest();
            cryptedByte = cipherSignature.doFinal(hesOtisak1);
            RandomAccessFile raf2 = new RandomAccessFile(hashMapsPath + "pass.hash", "rw");
            raf2.write(cryptedByte, 0, 512);
            raf2.close();
            out1.close();
            os1.close();
            //upisemo namesMap
            ByteArrayOutputStream out2 = new ByteArrayOutputStream();
            ObjectOutputStream os2 = new ObjectOutputStream(out2);
            os2.writeObject(namesMap);
            byte[] array2 = out2.toByteArray();
            md3.update(array2, 0, array2.length);
            fos3.write(cipherSymmetrically.doFinal(array2, 0, array2.length));
            fos3.flush();
            fos3.close();
            byte[] hesOtisak2 = md3.digest();
            cryptedByte = cipherSignature.doFinal(hesOtisak2);
            RandomAccessFile raf3 = new RandomAccessFile(hashMapsPath + "names.hash", "rw");
            raf3.write(cryptedByte, 0, 512);
            raf3.close();
            out2.close();
            os2.close();
        }
        catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IOException | IllegalBlockSizeException | BadPaddingException e)
        {
            callOptionPane(null, "Error serialising!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
    }
    private void end()
    {
        try
        {
            br.close();
            pw.close();
            clientSocket.close();
        }
        catch (IOException e)
        {
            callOptionPane(null, "Error finalising resources!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
        finally
        {
            callOptionPane(null, "Session " + sessionId + " finished.", "Error!", JOptionPane.INFORMATION_MESSAGE);
        }
    }
    private static void init() throws FileNotFoundException, IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchProviderException
    {
        Security.addProvider(new BouncyCastleProvider());
        File salt = new File(hashMapsPath + "salt.hash");
        File pass = new File(hashMapsPath + "pass.hash");
        File names = new File(hashMapsPath + "names.hash");
        if (salt.exists() && pass.exists() && names.exists())
        {
            //ako fajlovi postoje treba samo dekriptovati, provjeriti digitalni potpis i ucitati u objekt HasMap
            byte[] dataEncoded = null;
            byte[] cryptedByte = new byte[512];
            byte[] procitaniDigitalniPotpis = new byte[512];
            FileInputStream fis1 = new FileInputStream(salt);
            FileInputStream fis2 = new FileInputStream(pass);
            FileInputStream fis3 = new FileInputStream(names);
            MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
            Cipher aCipher;
            try
            {
                aCipher = Cipher.getInstance("RSA", "BC");
                aCipher.init(Cipher.DECRYPT_MODE, ServerThread.caCert.getPublicKey());
                fis1.read(cryptedByte);
                procitaniDigitalniPotpis = aCipher.doFinal(cryptedByte);
                //sesijski kljuc
                fis1.read(cryptedByte);
                dataEncoded = aCipher.doFinal(cryptedByte);
                md.update(dataEncoded);
                SecretKey sessionKey = new SecretKeySpec(dataEncoded, "AES");
                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
                cipher.init(Cipher.DECRYPT_MODE, sessionKey);
                int len = (int) salt.length() - 1024;
                byte[] data = new byte[len];
                int j = fis1.read(data);
                byte[] buffer = cipher.doFinal(data, 0, j);
                md.update(buffer);
                //od byte[] generisemo hashMap
                ByteArrayInputStream in = new ByteArrayInputStream(buffer);
                ObjectInputStream is = new ObjectInputStream(in);
                saltMap = (HashMap<String, byte[]>) is.readObject();
                in.close();
                is.close();
                fis1.close();
                byte[] generisaniPotpis = md.digest();
                if (!Arrays.equals(procitaniDigitalniPotpis, generisaniPotpis))
                {
                    callOptionPane(null, "Salt signature error!", "Error!", JOptionPane.ERROR_MESSAGE);
                    throw new Exception("Error");
                }
                //passMap
                md.reset();
                fis2.read(cryptedByte);
                procitaniDigitalniPotpis = aCipher.doFinal(cryptedByte);
                //sesijski kljuc
                fis2.read(cryptedByte);
                dataEncoded = aCipher.doFinal(cryptedByte);
                md.update(dataEncoded);
                SecretKey sessionKey1 = new SecretKeySpec(dataEncoded, "AES");
                Cipher cipher1 = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
                cipher1.init(Cipher.DECRYPT_MODE, sessionKey1);
                int len1 = (int) pass.length() - 1024;
                byte[] data1 = new byte[len1];
                int k = fis2.read(data1);
                byte[] buffer1 = cipher1.doFinal(data1, 0, k);
                md.update(buffer1);
                //od byte[] generisemo hashMap
                ByteArrayInputStream in1 = new ByteArrayInputStream(buffer1);
                ObjectInputStream is1 = new ObjectInputStream(in1);
                passMap = (HashMap<String, String>) is1.readObject();
                in1.close();
                is1.close();
                fis2.close();
                generisaniPotpis = md.digest();
                if (!Arrays.equals(procitaniDigitalniPotpis, generisaniPotpis))
                {
                    callOptionPane(null, "Digital signature error!", "Error!", JOptionPane.ERROR_MESSAGE);
                    throw new Exception("Error");
                }
                //namesMap
                md.reset();
                fis3.read(cryptedByte);
                procitaniDigitalniPotpis = aCipher.doFinal(cryptedByte);
                //sesijski kljuc
                fis3.read(cryptedByte);
                dataEncoded = aCipher.doFinal(cryptedByte);
                md.update(dataEncoded);
                SecretKey sessionKey2 = new SecretKeySpec(dataEncoded, "AES");
                Cipher cipher2 = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
                cipher2.init(Cipher.DECRYPT_MODE, sessionKey2);
                int len2 = (int) names.length() - 1024;
                byte[] data2 = new byte[len2];
                int l = fis3.read(data2);
                byte[] buffer2 = cipher1.doFinal(data2, 0, l);
                md.update(buffer2);
                //od byte[] generisemo hashMap
                ByteArrayInputStream in2 = new ByteArrayInputStream(buffer2);
                ObjectInputStream is2 = new ObjectInputStream(in2);
                namesMap = (HashMap<String, String>) is2.readObject();
                in2.close();
                is2.close();
                fis3.close();
                generisaniPotpis = md.digest();
                if (!Arrays.equals(procitaniDigitalniPotpis, generisaniPotpis))
                {
                    callOptionPane(null, "Digital signature error!", "Error!", JOptionPane.ERROR_MESSAGE);
                    throw new Exception("Error");
                }
            }
            catch (Exception e)
            {
                callOptionPane(null, "Error reading map!", "Error!", JOptionPane.ERROR_MESSAGE);
            }
        }
        else
        {
            //ako ne postoji napraviti hashMap, kriptovati i digitalno potpisati
            SecureRandom secureRand = new SecureRandom();
            saltMap = new HashMap<String, byte[]>();
            byte[] s1 = new byte[8];
            secureRand.nextBytes(s1);//izabere salt
            saltMap.put("korisnik1", s1);// mapira dati salt sa username-om u saltDB
            byte[] s2 = new byte[8];
            secureRand.nextBytes(s2);
            saltMap.put("korisnik2", s2);
            passMap = new HashMap<>();
            passMap.put("korisnik1", getHashPass("korisnik1", "1111"));//getHashPass vraca hesiranu vrijednost salt+passworda u formatu stringa
            passMap.put("korisnik2", getHashPass("korisnik2", "2222"));
            FileOutputStream fos1 = new FileOutputStream(salt);
            FileOutputStream fos2 = new FileOutputStream(pass);
            //generisemo kljuc
            KeyGenerator keyGenerator = keyGenerator = KeyGenerator.getInstance("AES", "BC");
            keyGenerator.init(128);
            SecretKey key = keyGenerator.generateKey();
            Cipher cipherSymmetrically;
            byte[] textBytes = null;
            byte[] cryptedByte = new byte[512];
            try
            {
                cipherSymmetrically = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
                cipherSymmetrically.init(Cipher.ENCRYPT_MODE, key);
                Cipher cipherSignature = Cipher.getInstance("RSA", "BC");
                cipherSignature.init(Cipher.ENCRYPT_MODE, ServerHelp.getPrivateKey());//potpis se radi privatnim, a provjerava javnim
                MessageDigest md = MessageDigest.getInstance("SHA-256", "BC");
                md.reset();
                fos1.write(new byte[512]);
                fos2.write(new byte[512]);
                // sesijski kljuc
                textBytes = key.getEncoded();
                md.update(textBytes);
                cryptedByte = cipherSignature.doFinal(textBytes);
                fos1.write(cryptedByte);
                fos2.write(cryptedByte);
                //upisemo saltMap
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                ObjectOutputStream os = new ObjectOutputStream(out);
                os.writeObject(saltMap);
                byte[] array = out.toByteArray();
                md.update(array, 0, array.length);
                fos1.write(cipherSymmetrically.doFinal(array, 0, array.length));
                fos1.flush();
                fos1.close();
                byte[] hesOtisak = md.digest();
                cryptedByte = cipherSignature.doFinal(hesOtisak);
                RandomAccessFile raf1 = new RandomAccessFile(hashMapsPath + "salt.hash", "rw");
                raf1.write(cryptedByte, 0, 512);
                raf1.close();
                out.close();
                os.close();
                //upisemo passMap
                ByteArrayOutputStream out1 = new ByteArrayOutputStream();
                ObjectOutputStream os1 = new ObjectOutputStream(out1);
                os1.writeObject(passMap);
                byte[] array1 = out1.toByteArray();
                md.update(array1, 0, array1.length);
                fos2.write(cipherSymmetrically.doFinal(array1, 0, array1.length));
                fos2.flush();
                fos2.close();
                byte[] hesOtisak1 = md.digest();
                cryptedByte = cipherSignature.doFinal(hesOtisak1);
                RandomAccessFile raf2 = new RandomAccessFile(hashMapsPath + "pass.hash", "rw");
                raf2.write(cryptedByte, 0, 512);
                raf2.close();
                out1.close();
                os1.close();
            }
            catch (NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
            {
                callOptionPane(null, "Error in init method!", "Error!", JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    public static void callOptionPane(Component comp, Object message, String title, int messageType)
    {
        JOptionPane novi = new JOptionPane();
        novi.showMessageDialog(comp, message, title, messageType);
    }
}
