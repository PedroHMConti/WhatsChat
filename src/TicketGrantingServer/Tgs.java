package TicketGrantingServer;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class Tgs  {
    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(4998);
        Socket socket = serverSocket.accept();
        System.out.println("cliente conectou ao TGS");
    }
}
