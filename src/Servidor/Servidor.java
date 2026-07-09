package Servidor;

import criptografia.Cifra;
import criptografia.FuncaoDerivacaoChave;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HexFormat;
import java.util.Scanner;

public class Servidor {

    private static final String SENHA_V = "senha_servidor";
    private static final String SALT    = "unb.br";

    public static void main(String[] args) throws Exception {
        byte[] kV = FuncaoDerivacaoChave.derivarChave(SENHA_V, SALT);
        System.out.println("Servidor aguardando na porta 4997...");
        System.out.println("K_v: " + HexFormat.of().formatHex(kV));

        ServerSocket serverSocket = new ServerSocket(4997);
        while (true) {
            Socket socket = serverSocket.accept();
            System.out.println("Cliente conectou ao Servidor");

            try (socket;
                 var entrada = new DataInputStream(socket.getInputStream());
                 var saida = new DataOutputStream(socket.getOutputStream())) {

                // ── lê mensagem (5): ID_v ‖ Ticket_v ‖ Authenticator_c ──
                String idV = entrada.readUTF();
                System.out.println("ID_v recebido: " + idV);

                int tamTicketV = entrada.readInt();
                byte[] ticketV = new byte[tamTicketV];
                entrada.readFully(ticketV);

                int tamAuth = entrada.readInt();
                byte[] authCifrado = new byte[tamAuth];
                entrada.readFully(authCifrado);

                // ── decifra Ticket_v com K_v → obtém K_c,v e dados do cliente ──
                byte[] mioloTicket = Cifra.decifrar(kV, ticketV);
                DataInputStream disTicket = new DataInputStream(new ByteArrayInputStream(mioloTicket));

                int tamKcV = disTicket.readInt();
                byte[] kcV = new byte[tamKcV];
                disTicket.readFully(kcV);
                String idC_ticket = disTicket.readUTF();
                String adC_ticket = disTicket.readUTF();
                String idV_ticket = disTicket.readUTF();
                long ts4 = disTicket.readLong();
                long lifetime4 = disTicket.readLong();
                System.out.println("Ticket_v decifrado — ID_C: " + idC_ticket + " | K_c,v: " + HexFormat.of().formatHex(kcV));

                // ── decifra Authenticator_c com K_c,v → obtém ID_C, AD_C, TS5 ──
                byte[] mioloAuth = Cifra.decifrar(kcV, authCifrado);
                DataInputStream disAuth = new DataInputStream(new ByteArrayInputStream(mioloAuth));

                String idC_auth = disAuth.readUTF();
                String adC_auth = disAuth.readUTF();
                long ts5 = disAuth.readLong();
                System.out.println("Autenticador decifrado — ID_C: " + idC_auth + " | TS5: " + ts5);

                // ── verifica: ID_C e AD_C do autenticador devem bater com o ticket ──
                if (!idC_ticket.equals(idC_auth) || !adC_ticket.equals(adC_auth)) {
                    System.out.println("ALERTA: autenticador não confere com o ticket!");
                    continue;
                }
                System.out.println("Cliente autenticado com sucesso: " + idC_auth);

                // ── mensagem (6): E(K_c,v, [TS5 + 1]) — prova que decifrou o autenticador ──
                ByteArrayOutputStream bufMsg6 = new ByteArrayOutputStream();
                DataOutputStream dosMsg6 = new DataOutputStream(bufMsg6);
                dosMsg6.writeLong(ts5 + 1);
                byte[] mensagem6 = Cifra.cifrar(kcV, bufMsg6.toByteArray());

                saida.writeInt(mensagem6.length);
                saida.write(mensagem6);
                saida.flush();
                System.out.println("Mensagem (6) enviada: E(K_c,v, [TS5+1])");

                // ── chat cifrado com K_c,v ──
                chat(entrada, saida, kcV, idC_auth);

            } catch (Exception e) {
                System.out.println("Erro com o cliente: " + e.getMessage());
            }
        }
    }
    public static void chat(DataInputStream entrada, DataOutputStream saida, byte[] kcV, String idC) throws Exception {
        Scanner scanner = new Scanner(System.in);

        // thread separada para receber mensagens do cliente em paralelo
        Thread receptor = new Thread(() -> {
            try {
                while (true) {
                    int tam = entrada.readInt();
                    byte[] cifrado = entrada.readNBytes(tam);
                    byte[] texto   = Cifra.decifrar(kcV, cifrado);
                    System.out.println("[" + idC + "]: " + new String(texto));
                }
            } catch (Exception e) {
                System.out.println("Cliente desconectou.");
            }
        });
        receptor.setDaemon(true);
        receptor.start();

        System.out.println("Chat iniciado com " + idC + ". Digite suas mensagens (SAIR para encerrar):");
        while (true) {
            String linha = scanner.nextLine();
            if ("SAIR".equalsIgnoreCase(linha)) break;
            byte[] cifrado = Cifra.cifrar(kcV, linha.getBytes());
            saida.writeInt(cifrado.length);
            saida.write(cifrado);
            saida.flush();
        }
    }
}