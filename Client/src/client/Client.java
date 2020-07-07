package client;

import forms.ChangesOfFile;
import forms.ChooseFile;
import forms.FileList;
import forms.Login;
import forms.Switchboard;
import forms.SwitchboardFile;
import java.awt.Component;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Scanner;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Client
{
    public static final int PORT = 4444;
    public static String alg = "AES/ECB/PKCS5Padding";// simetricni
    public static String caPath = ".//resources/cacert.cer";
    public static String caKeyPath = ".//resources/caKey.der";
    public static SecretKey sessionKey;
    public static Socket socket;
    public static BufferedReader br;
    public static PrintWriter pw;
    public static InputStream is;
    public static OutputStream os;
    public static X509Certificate userCert = null;
    public static X509Certificate caCert = null;
    private static Object lock = new Object();
    public static void main(String[] args)
    {
        InetAddress adresa = null;
        String action = "", responce = "";
        Security.addProvider(new BouncyCastleProvider());
        try
        {
            adresa = InetAddress.getLocalHost();//ako se radi sa dva laptopa onda ce ovde imati ip adresu tog drugog laptopa
        }
        catch (UnknownHostException e)
        {
            callOptionPane(null, "Error geting localhost!", "Error!", JOptionPane.INFORMATION_MESSAGE);
        }
        try
        {
            socket = new Socket(adresa, PORT);
            os = socket.getOutputStream();
            is = socket.getInputStream();
            br = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            pw = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            caCert = (X509Certificate) cf.generateCertificate(new FileInputStream(caPath));
            byte[] bytes = new byte[2 * 1024 * 1024]; //CITA PO BLOKOVIMA OD 2MB
            int count = 0;
            try
            {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BC");
                keyGen.init(128);//kljuc duzine 128
                sessionKey = keyGen.generateKey();
            }
            catch (NoSuchAlgorithmException | NoSuchProviderException e1)
            {
                callOptionPane(null, "Error generating 128 in the beggining!", "Error!", JOptionPane.ERROR_MESSAGE);
            }
            try
            {
                bytes = ClientHelp.encryptAsymetric(caCert.getPublicKey(), sessionKey.getEncoded()); //vrati smao enkriptovan sesijski
            }
            catch (Exception e)
            {
                callOptionPane(null, "Certificate encription error!", "Error!", JOptionPane.ERROR_MESSAGE);
                //e.printStackTrace();
            }
            os.write(bytes);
            responce = br.readLine();
            if (!responce.equals("Session key success!"))
            {
                callOptionPane(null, "Session key not accepted at Server!", "Error!", JOptionPane.ERROR_MESSAGE);
                return;
            }
            //prvo saljemo username i lozinku na provjeru
            Scanner scan = new Scanner(System.in);
            boolean login = false;
            String username = "", password = "";
            while (!login)
            {
                Login loginForm = new Login(lock);
                loginForm.setVisible(true);
                waitHelper(loginForm, lock);
                username = loginForm.getUsername();
                password = loginForm.getPassword();
                String data = username + "#" + password;
                ClientHelp.sendSymetric(data.getBytes());
                responce = ClientHelp.reciveSymetric(); //ako je uredu vratice "OK"
                if (!responce.equals("OK"))
                {
                    callOptionPane(null, "Username or password incorrect!", "Error!", JOptionPane.ERROR_MESSAGE);
                }
                else
                {
                    //sada saljemo certifikat
                    /*Za fleksibilnost koda*/
                    ChooseFile choosef = new ChooseFile(lock);
                    choosef.setVisible(true);
                    Client.waitHelper(choosef, lock);
                    String path = choosef.getPath();
                    /**
                     * ********************
                     */
                    bytes = new byte[2 * 1024 * 1024];
                    File file = new File(path);
                    InputStream fis = new FileInputStream(file);
                    count = fis.read(bytes);
                    fis.close();
                    byte[] tmp = new byte[count];
                    InputStream i = new FileInputStream(path);
                    i.read(tmp);
                    i.close();
                    ClientHelp.sendSymetric(tmp);
                    responce = br.readLine();
                    if (responce.equals("Validation success!"))
                    {
                        login = true;
                    }
                    else
                    {
                        callOptionPane(null, "Unsuccesful validation!", "Error!", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
            boolean izlaz = false;
            while (!izlaz)
            {
                Switchboard switchb = new Switchboard(lock);
                switchb.setVisible(true);
                waitHelper(switchb, lock);
                action = switchb.getAction();
                if (action.equals("1"))
                {
                    ClientHelp.sendSymetric(action.getBytes());
                    responce = ClientHelp.reciveSymetric();
                    if (!responce.equals("No files on server!"))
                    {
                        ArrayList list = reformFiles(responce);
                        FileList choosing = new FileList(lock, list);
                        choosing.setVisible(true);
                        waitHelper(choosing, lock);
                        action = choosing.getFile();
                        ClientHelp.sendSymetric(action.getBytes()); //slanje indeksa izabranog fajla
                        responce = new String(ClientHelp.reciveSymetric());
                        if (responce.equals("Wrong file choise!"))
                        {
                            callOptionPane(null, "File not valid!", "Error!", JOptionPane.ERROR_MESSAGE);
                        }
                        else
                        {
                            SwitchboardFile sbfile = new SwitchboardFile(lock);
                            sbfile.setVisible(true);
                            waitHelper(sbfile, lock);
                            action = sbfile.getAction();
                            if (action.equals("1"))
                            {// download file
                                ClientHelp.sendSymetric(action.getBytes());//slanje opcije
                                String fileToGet = new String(ClientHelp.reciveSymetric());//prijem naziva fajla
                                if (fileToGet.equals("NOK"))
                                {
                                }
                                else
                                {
                                    ClientHelp.sendSymetric("OK".getBytes());
                                    try
                                    {
                                        ClientHelp.reciveFile(fileToGet, username);
                                    }
                                    catch (Exception e)
                                    {
                                        e.printStackTrace();
                                    }
                                }
                            }
                            else if (action.equals("2"))
                            {//izmjena fajla
                                ClientHelp.sendSymetric(action.getBytes());
                                ClientHelp.reciveSymetric();
                                ChooseFile choosef = new ChooseFile(lock);
                                choosef.setVisible(true);
                                Client.waitHelper(choosef, lock);
                                String path = choosef.getPath();
                                if (ClientHelp.sendFile(scan, false, path))
                                {
                                    callOptionPane(null, "File changed!", "Success!", JOptionPane.INFORMATION_MESSAGE);
                                }
                            }
                            else if (action.equals("3"))
                            {//spisak izmjena
                                ClientHelp.sendSymetric(action.getBytes());
                                String num = ClientHelp.reciveSymetric();
                                if (num.equals("File has no changes."))
                                {
                                    callOptionPane(null, "File does not have changes!", "Info!", JOptionPane.INFORMATION_MESSAGE);
                                }
                                else
                                {
                                    String[] tempString = num.split("\n");
                                    ArrayList<String> changes = new ArrayList<>();
                                    for (String item : tempString)
                                    {
                                        changes.add(item);
                                    }
                                    ChangesOfFile cofile = new ChangesOfFile(lock, changes);
                                    cofile.setVisible(true);
                                    Client.waitHelper(cofile, lock);
                                }
                            }
                            else if (action.equals("4"))
                            {//nazad
                                ClientHelp.sendSymetric(action.getBytes());
                            }
                        }
                    }
                    else
                    {
                        callOptionPane(null, "No files!", "Error!", JOptionPane.ERROR_MESSAGE);
                    }
                }
                else if (action.equals("2"))
                {//upload fajla
                    ClientHelp.sendSymetric(action.getBytes());
                    responce = ClientHelp.reciveSymetric();//OK
                    ChooseFile choosef = new ChooseFile(lock);
                    choosef.setVisible(true);
                    Client.waitHelper(choosef, lock);
                    String path = choosef.getPath();
                    if (ClientHelp.sendFile(scan, true, path))
                    {
                        callOptionPane(null, "File uploaded!", "Success!", JOptionPane.INFORMATION_MESSAGE);
                    }
                }
                else if (action.equals("3"))
                {//logout
                    ClientHelp.sendSymetric(action.getBytes());
                    izlaz = true;
                }
                else
                {
                    callOptionPane(null, "Invalid option!", "Error!", JOptionPane.ERROR_MESSAGE);
                }
            }
            scan.close();
            br.close();
            pw.close();
            os.close();
            socket.close();
            callOptionPane(null, "END!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
        catch (IOException e)
        {
            callOptionPane(null, "Error instantiating client socket!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
        catch (CertificateException e)
        {
            callOptionPane(null, "Error generating certificates" + "!", "Error!", JOptionPane.ERROR_MESSAGE);
        }
    }
    public static void waitHelper(JFrame frame, Object lock)
    {
        Thread t = new Thread()
        {
            public void run()
            {
                synchronized (lock)
                {
                    while (frame.isVisible())
                    {
                        try
                        {
                            lock.wait();
                        }
                        catch (InterruptedException e)
                        {
                            e.printStackTrace();
                        }
                    }
                }
            }
        };
        t.start();
        try
        {
            t.join();
        }
        catch (Exception e)
        {
        }
    }
    public static void callOptionPane(Component comp, Object message, String title, int messageType)
    {
        JOptionPane novi = new JOptionPane();
        novi.showMessageDialog(comp, message, title, messageType);
    }
    public static ArrayList<String> reformFiles(String files)
    {
        String[] lines = files.split("\n");
        ArrayList<String> list = new ArrayList<>();
        for (String line : lines)
        {
            String tmp = line.split(" ")[2];
            tmp = tmp.split("\r")[0];
            /*if(!"null".equals(tmp))*/
            list.add(tmp);
        }
        return list;
    }
}
