import java.io.IOException;
import java.io.PrintStream;
import java.net.Socket;
import java.util.Scanner;

public class Cliente {

    public static void main(String[] args) throws IOException {
        Socket socket = new Socket("localhost", 5000);
        Scanner sc = new Scanner(System.in);

        ClienteThread clienteThread = new ClienteThread(socket);
        clienteThread.start();

        PrintStream saida = new PrintStream(socket.getOutputStream(),true);
        String console;
        while ((console = sc.nextLine()) != null) {
            saida.println(console);
        }


    }
}
