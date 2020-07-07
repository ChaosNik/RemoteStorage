package server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import javax.swing.JOptionPane;
import static server.ServerThread.callOptionPane;

public class Server
{
    public static final int SERVER_PORT = 4444;
    public static void main(String[] args) throws IOException
    {
        ServerSocket serverSocket = null;
        try
        {
            serverSocket = new ServerSocket(SERVER_PORT);
            callOptionPane(null, "Server starting!", "Starting...!", JOptionPane.INFORMATION_MESSAGE);
            int i = 0;
            while (true)
            {
                Socket client = serverSocket.accept();
                new ServerThread(client, i++);
            }
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }
        if (serverSocket != null)
        {
            serverSocket.close();
        }
    }
}
