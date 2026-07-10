package TicketGrantingServer;

import AutenticationServer.ASRepository;
import criptografia.Cifra;
import criptografia.FuncaoDerivacaoChave;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HexFormat;

public class Tgs  {
    public static void main(String[] args) throws Exception {
        TgsModel tgs = new TgsModel("TGS@TRABALHOSEC", "senha_tgs");
        ServerSocket serverSocket = new ServerSocket(4998);
        while (true) {
            Socket socket = serverSocket.accept();      // bloqueia até alguém conectar
            System.out.println("cliente conectou ao AS");
            System.out.println("--------------------------------------");
            try(socket;
                var entrada = new DataInputStream(socket.getInputStream());
                var saida   = new DataOutputStream(socket.getOutputStream())){
                //le a mensagem
                Mensagem3 msg3 = leMensagem3(entrada);
                System.out.println("--------------------------------------");

                //verificacao do tgs
                //decifra o ticket e salva em uma variavel
                byte[] mioloTicket = decifrarTicket_tgs(tgs, msg3.getTicket_tgs());
                TicketTgs ticketTgs = leTicket_tgs(mioloTicket);

                //decifra o autenticador e salva em uma variavel
                Autenticador autenticador = decriptarAutenticador(ticketTgs.getK_c_tgs(), msg3.getAuthenticator_c());
                //verifica validade e autenticidade do ticket comparando com autenticador
                if(verificarValidadeTicket_tgs(ticketTgs) && comparaAutenticadorETicket(ticketTgs,autenticador)){
                    System.out.println("cliente é o dono do ticket enviado");
                    enviaMensagem4(saida, ticketTgs, msg3.getID_V());
                }else {
                    System.out.println("ALEEERTA DE INTRUSÃO !!!!");
                    break;
                }
            }
        }
    }
    private static final SecureRandom RANDOM   = new SecureRandom();
    private static final long         LIFETIME = 8 * 60 * 60 * 1000L; // 8h em ms

    public static void enviaMensagem4(DataOutputStream saida, TicketTgs ticketTgs, String idV) throws Exception {
        // gera K_c,v — chave de sessão entre cliente e serviço
        byte[] kcV = new byte[32];
        RANDOM.nextBytes(kcV);

        // obtém K_v — chave de longo prazo do serviço (derivada da senha do serviço)
        byte[] kV = FuncaoDerivacaoChave.derivarChave("senha_" + idV.toLowerCase(), "unb.br");

        // monta e cifra Ticket_v
        byte[] ticketV = criaTicket_V(ticketTgs, idV, kV, kcV);

        // monta mensagem (4): E(K_c,tgs, [K_c,v ‖ ID_v ‖ TS₄ ‖ Ticket_v])
        long ts4 = System.currentTimeMillis();
        ByteArrayOutputStream bufMsg = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bufMsg);
        dos.writeInt(kcV.length);
        dos.write(kcV);
        dos.writeUTF(idV);
        dos.writeLong(ts4);
        dos.writeInt(ticketV.length);
        dos.write(ticketV);
        byte[] mensagem4 = Cifra.cifrar(ticketTgs.getK_c_tgs(), bufMsg.toByteArray());

        // envia ao cliente
        saida.writeInt(mensagem4.length);
        saida.write(mensagem4);
        saida.flush();
        System.out.println("mensagem (4) enviada: " + mensagem4.length + " bytes");
    }

    // Ticket_v = E(K_v, [K_c,v ‖ ID_C ‖ AD_C ‖ ID_v ‖ TS₄ ‖ Lifetime₄])
    public static byte[] criaTicket_V(TicketTgs ticketTgs, String idV, byte[] kV, byte[] kcV) throws Exception {
        long ts4 = System.currentTimeMillis();

        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(buf);
        dos.writeInt(kcV.length);                            // K_c,v
        dos.write(kcV);
        dos.writeUTF(ticketTgs.getID_C());                   // ID_C
        dos.writeUTF(ticketTgs.getAD_C().getHostAddress()); // AD_C
        dos.writeUTF(idV);                                   // ID_v
        dos.writeLong(ts4);                                  // TS₄
        dos.writeLong(LIFETIME);                             // Lifetime₄

        return Cifra.cifrar(kV, buf.toByteArray());          // E(K_v, miolo)
    }

    public static Mensagem3 leMensagem3(DataInputStream entrada) throws IOException {
        System.out.println("recebendo mensagem (3)");
        String ID_V = entrada.readUTF();
        System.out.println("ID_V: " + ID_V);

        int tamTicket = entrada.readInt();
        byte[] ticket_tgs = new byte[tamTicket];
        entrada.readFully(ticket_tgs);
        System.out.println("Ticket_tgs recebido: " + tamTicket + " bytes");

        int tamAuth = entrada.readInt();
        byte[] authenticator_c = new byte[tamAuth];
        entrada.readFully(authenticator_c);
        System.out.println("Authenticator_c recebido: " + tamAuth + " bytes");
        return new Mensagem3(ID_V, ticket_tgs, authenticator_c);
    }

    public static byte[] geraK_tgs(TgsModel tgs) throws Exception {
        ASRepository repo = new ASRepository();
        return FuncaoDerivacaoChave.derivarChave(tgs.getSenha(), "unb.br");
    }
    public static byte[] decifrarTicket_tgs(TgsModel tgs,byte[] ticket_tgs)throws Exception{
        return Cifra.decifrar(geraK_tgs(tgs),ticket_tgs);
    };

    public static TicketTgs leTicket_tgs(byte[] mioloDecifrado) throws Exception {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(mioloDecifrado));

        // lê na MESMA ORDEM que o AS escreveu:
        // writeInt(kcTgs.length) ‖ write(kcTgs) ‖ writeUTF(idC) ‖ writeUTF(adC) ‖ writeLong(ts2)
        int tamKcTgs = dis.readInt();
        byte[] kcTgs = new byte[tamKcTgs];
        dis.readFully(kcTgs);

        String idC  = dis.readUTF();
        String adCS = dis.readUTF();
        long ts2    = dis.readLong();

        TicketTgs ticket = new TicketTgs();
        ticket.setK_c_tgs(kcTgs);
        ticket.setID_C(idC);
        ticket.setAD_C(InetAddress.getByName(adCS));    // usa o que estava no ticket
        ticket.setTS2(Instant.ofEpochMilli(ts2).atZone(ZoneId.systemDefault()).toLocalDateTime());
        return ticket;
    }

    public static Boolean verificarValidadeTicket_tgs(TicketTgs ticketTgs) {
        System.out.println("--------------------------------------");
        System.out.println("verificarValidadeTicket_tgs");
        long ts2Millis = ticketTgs.getTS2()
                .atZone(ZoneId.systemDefault())
                .toInstant()
                .toEpochMilli();
        long decorrido = System.currentTimeMillis() - ts2Millis;
        System.out.println("Tempo decorrido desde emissão: " + decorrido + " ms");
        return decorrido < 5 * 60 * 1000L;   // válido se emitido há menos de 5 minutos
    }

    public static Autenticador decriptarAutenticador(byte[] k_c_tgs, byte[] autenticadorCifrado) throws Exception {
        // decifra com K_c,tgs para obter [ID_C ‖ AD_C ‖ TS]
        byte[] miolo = Cifra.decifrar(k_c_tgs, autenticadorCifrado);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(miolo));

        // lê na MESMA ORDEM que criaAutenticador escreveu:
        // writeUTF(idc) ‖ writeUTF(adC) ‖ writeLong(TS)
        String idC  = dis.readUTF();
        String adCS = dis.readUTF();
        long ts     = dis.readLong();

        Autenticador auth = new Autenticador();
        auth.setIdc(idC);
        auth.setAdc(InetAddress.getByName(adCS));
        auth.setTS3(Instant.ofEpochMilli(ts).atZone(ZoneId.systemDefault()).toLocalDateTime());
        return auth;
    }

    public static Boolean comparaAutenticadorETicket(TicketTgs ticketTgs,Autenticador auth)throws Exception{
        if((ticketTgs.getAD_C().equals(auth.getAdc())) && (ticketTgs.getID_C().equals(auth.getIdc()))){
            return true;
        }else{
            System.out.println("comparaAutenticadorETicket deu erro ");
            System.out.println("ticketTgs.getAD_C(): "+ ticketTgs.getAD_C() );
            System.out.println("auth.getAdc(): "+  auth.getAdc());
            System.out.println("ticketTgs.getID_C(): "+ ticketTgs.getID_C());
            System.out.println("auth.getIdc(): "+  auth.getIdc());
            return false;
        }
    }
}
