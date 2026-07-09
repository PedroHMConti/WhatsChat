package AutenticationServer;
import criptografia.Cifra;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.HexFormat;

public class AS {

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(4999);
        System.out.println("AS aguardando na porta 4999...");

        while (true) {                                  // atende um cliente após o outro
            Socket socket = serverSocket.accept();      // bloqueia até alguém conectar
            System.out.println("cliente conectou ao AS");

            try (socket;
                 var entrada = new DataInputStream(socket.getInputStream());
                 var saida   = new DataOutputStream(socket.getOutputStream())) {

                System.out.println("Fase (a) recebendo mensagem (1): ID_C ‖ ID_tgs ‖ TS1");
                String idC = entrada.readUTF();
                String idTgs = entrada.readUTF();
                long ts1     = entrada.readLong();
                System.out.println("idC: " + idC);
                System.out.println("idTgs: " + idTgs);
                System.out.println("ts1: " + ts1);
                //buscar o AD_C
                InetAddress adC = socket.getInetAddress();
                // 2. PROCESSA: busca K_c, sorteia K_c,tgs, cifra a msg (2)
                byte[] mensagem2 = montarMensagem2(idC,idTgs,adC);
                System.out.println(HexFormat.of().formatHex(mensagem2));

                // 3. responde mensagem (2)
                saida.writeInt(mensagem2.length);
                saida.write(mensagem2);

            } catch (IOException e) {
                System.out.println("Erro com o cliente: " + e.getMessage());
            }
            // socket fecha sozinho (try-with-resources), volta ao accept()
        }
    }
    //inicializacoes
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final long LIFETIME = 8 * 60 * 60 * 1000L; // 8h em ms
    private static final ASRepository repository = new ASRepository() ;


    public static byte[] montarMensagem2(String idC, String idTgs, InetAddress adC) throws Exception {
        byte[] kc   = repository.find_K_C(idC);
        byte[] kTgs = repository.find_K_C(idTgs);
        byte[] kcTgs = new byte[32];
        RANDOM.nextBytes(kcTgs);
        long ts2 = System.currentTimeMillis();

        // ── Ticket_tgs: monta com DataOutputStream, depois cifra ──
        ByteArrayOutputStream bufTicket = new ByteArrayOutputStream();
        DataOutputStream dosTicket = new DataOutputStream(bufTicket);
        dosTicket.writeInt(kcTgs.length);   // tamanho do byte[]
        dosTicket.write(kcTgs);             // os bytes
        dosTicket.writeUTF(idC);            // ID_C (tamanho embutido automaticamente)
        dosTicket.writeUTF(adC.getHostAddress());
        dosTicket.writeLong(ts2);
        byte[] ticketTgs = Cifra.cifrar(kTgs, bufTicket.toByteArray());

        // ── Miolo da msg (2): mesma técnica ──
        ByteArrayOutputStream bufMsg = new ByteArrayOutputStream();
        DataOutputStream dosMsg = new DataOutputStream(bufMsg);
        dosMsg.writeInt(kcTgs.length);
        dosMsg.write(kcTgs);
        dosMsg.writeUTF(idTgs);
        dosMsg.writeLong(ts2);
        dosMsg.writeInt(ticketTgs.length);  // Ticket_tgs é byte[] variável
        dosMsg.write(ticketTgs);

        return Cifra.cifrar(kc, bufMsg.toByteArray());
    }
}