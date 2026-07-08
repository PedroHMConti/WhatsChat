package Cliente;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;

public class ClienteThread extends Thread {

    private Socket socket;

    public ClienteThread(Socket socket) {
        this.socket = socket;
    }
    @Override
    public void run() {
        try{

            InputStreamReader isr = new InputStreamReader(socket.getInputStream());
            BufferedReader reader = new BufferedReader(isr);
            String x;

            while ((x = reader.readLine()) != null) {
                System.out.println("Servidor : " + x );
            }
        }catch(Exception e){
            System.out.println("Erro no servidor");
        }
    }
}
