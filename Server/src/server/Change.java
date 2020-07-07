package server;

import java.io.Serializable;

public class Change implements Serializable
{
    private String username;
    private String fileName;
    private String date;
    public Change(String u, String f, String d)
    {
        this.username = u;
        this.fileName = f;
        this.date = d;
    }
    public String getUsername()
    {
        return username;
    }
    public String getFileName()
    {
        return fileName;
    }
    public String getDate()
    {
        return date;
    }
}
