package Servidor;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.Socket;

public class ServidorThread extends Thread {

    private Socket socket;

    public ServidorThread(Socket socket) {
        this.socket = socket;
    }
    @Override
    public void run(){
        try{
            BufferedReader input = new BufferedReader(new InputStreamReader(System.in));
            InputStreamReader isr = new InputStreamReader(socket.getInputStream());
            BufferedReader reader = new BufferedReader(isr);
            String x;

            while ((x = reader.readLine()) != null) {
                System.out.println("Cliente.Cliente: " + x );
            }
        }catch(Exception e){
            System.out.println(e.getMessage());
        }
    }

}
