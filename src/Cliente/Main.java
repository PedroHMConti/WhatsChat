package Cliente;

import java.io.IOException;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) throws IOException {
        ServerSocket serverSocket = new ServerSocket(5000);
        Socket socket = serverSocket.accept();
        System.out.println("cliente conectou");

        //thread que recebe mensagens
        ServidorThread servidorThread = new ServidorThread(socket);
        servidorThread.start();

        //thread que envia
        PrintStream out = new PrintStream(socket.getOutputStream(),true );
        Scanner in = new Scanner(System.in);
        String linha;
        while((linha = in.nextLine()) != null) {
            out.println(linha);
        }
    }
}