package Cliente;

import criptografia.Cifra;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.HexFormat;

import static criptografia.Cifra.decifrar;
import static criptografia.FuncaoDerivacaoChave.derivarChave;

public class Cliente {
    public static void main(String[] args) throws Exception {
        ClienteModel cliente = new ClienteModel("Pedro", "TGS@TRABALHOSEC", "senha");
        Mensagem2_Decifrada msg2 = new Mensagem2_Decifrada();

        // ===== FASE (a): troca com o AS =====
        try (Socket socketAS = new Socket("localhost", 4999);
             var saida   = new DataOutputStream(socketAS.getOutputStream());
             var entrada = new DataInputStream(socketAS.getInputStream())) {
            escreveMensagem1(saida,cliente);
            lerMensagem2(entrada, msg2);

        } catch (Exception e) {
            e.printStackTrace();
        }

        // ===== FASE (b): agora sim conecta ao TGS, usando ticketTgs =====
         try (Socket socketTGS = new Socket("localhost", 4998);
              var saida   = new DataOutputStream(socketTGS.getOutputStream());
              var entrada = new DataInputStream(socketTGS.getInputStream())) {
            escreveMensagem3(saida, cliente, msg2);
            Mensagem4_Decifrada msg4 = lerMensagem4(entrada, msg2.getKcTgs());
         }catch (Exception e){
             e.printStackTrace();
         }
        // ===== FASE (c): depois conecta ao serviço, usando ticketV =====
    }
    public static void escreveMensagem1(DataOutputStream saida,ClienteModel cliente) throws IOException {
        // mensagem (1): ID_C ‖ ID_tgs ‖ TS1
        System.out.println("fase (a) informando mensagem (1): ID_C ‖ ID_tgs ‖ TS1");
        System.out.println("ID_C: " + cliente.getID_C());
        System.out.println("ID_tgs: " + cliente.getID_tgs());
        System.out.println("TS1: "+System.currentTimeMillis() );
        saida.writeUTF(cliente.getID_C());
        saida.writeUTF(cliente.getID_tgs());
        saida.writeLong(System.currentTimeMillis());
        saida.flush();
        System.out.println("mensagem (1) enviada com sucesso!");
    }


    public static Mensagem2_Decifrada lerMensagem2(DataInputStream entrada,Mensagem2_Decifrada msg2) throws Exception {
        // mensagem (2): E(K_c, [K_c,tgs ‖ ID_tgs ‖ TS2 ‖ Ticket_tgs])  — LER
        System.out.println("Recebe mensagem (2): E(K_c, [K_c,tgs ‖ ID_tgs ‖ TS2 ‖ Ticket_tgs]) ");

        // ── deriva K_c (tem que dar a MESMA chave que o AS usou) ──
        byte[]kc = derivarChave("senha", "unb.br");
        System.out.println("K_C: " + HexFormat.of().formatHex(kc));

        // ── lê a mensagem (2) da rede ──

        int tamMsg2 = entrada.readInt();
        byte[] mensagem2 = entrada.readNBytes(tamMsg2);

        // ── decifra com K_c e desmonta o miolo NA MESMA ORDEM do AS ──
        byte[] miolo = Cifra.decifrar(kc, mensagem2);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(miolo));

        // 1. writeInt(kcTgs.length)  →  readInt
        int tamKcTgs = dis.readInt();
        // 2. write(kcTgs)            →  readFully
        byte[]kcTgs = new byte[tamKcTgs];
        dis.readFully(kcTgs);   // preenche o array in-place, retorna void
        msg2.setKcTgs(kcTgs);
        // 3. writeUTF(idTgs)         →  readUTF
        String idTgs = dis.readUTF();
        long ts2 = dis.readLong();
        msg2.setTS2(Instant.ofEpochMilli(ts2)
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime());
        // 5. writeInt(ticketTgs.length) → readInt
        int tamTicket = dis.readInt();
        // 6. write(ticketTgs)        →  readFully
        byte[]ticketTgs = new byte[tamTicket];
        dis.readFully(ticketTgs);   // bloco opaco — cifrado com K_tgs, guarda p/ a fase (b)
        msg2.setTicket_tgs(ticketTgs);

        System.out.println("K_c,tgs recebida: " + HexFormat.of().formatHex(kcTgs));
        System.out.println("ID_tgs: " + idTgs);
        System.out.println("Ticket_tgs (encriptado, " + tamTicket + " bytes) guardado.");
        return msg2;
    }
    public static Mensagem4_Decifrada lerMensagem4(DataInputStream entrada, byte[] kcTgs) throws Exception {
        System.out.println("Recebe mensagem (4): E(K_c,tgs, [K_c,v ‖ ID_v ‖ TS₄ ‖ Ticket_v])");

        // lê e decifra com K_c,tgs
        int tam = entrada.readInt();
        byte[] mensagem4 = entrada.readNBytes(tam);
        byte[] miolo = Cifra.decifrar(kcTgs, mensagem4);
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(miolo));

        // desmonta na MESMA ORDEM que o TGS montou:
        // writeInt(kcV.length) ‖ write(kcV) ‖ writeUTF(idV) ‖ writeLong(ts4) ‖ writeInt(ticketV.length) ‖ write(ticketV)
        int tamKcV = dis.readInt();
        byte[] kcV = new byte[tamKcV];
        dis.readFully(kcV);

        String idV = dis.readUTF();
        long ts4   = dis.readLong();


        int tamTicketV = dis.readInt();
        byte[] ticketV = new byte[tamTicketV];
        dis.readFully(ticketV);

        Mensagem4_Decifrada msg4 = new Mensagem4_Decifrada();
        msg4.setKcV(kcV);
        msg4.setIdV(idV);
        msg4.setTs4(Instant.ofEpochMilli(ts4).atZone(ZoneId.systemDefault()).toLocalDateTime());
        msg4.setTicketV(ticketV);

        System.out.println("K_c,v recebida: " + HexFormat.of().formatHex(kcV));
        System.out.println("ID_v: " + idV);
        System.out.println("Ticket_v (encriptado, " + tamTicketV + " bytes) guardado.");
        return msg4;
    }

    public static void escreveMensagem3(DataOutputStream saida,ClienteModel cliente,Mensagem2_Decifrada msg2) throws Exception {
        System.out.println("fase (b) informando mensagem (3): C -> TGS:  ID_V ‖ Ticket_tgs ‖ Authenticator_c");
        System.out.println("ID_V: " + "Servidor");
        System.out.println("Ticket_tgs: " + msg2.getTicket_tgs().length + " bytes guardado." );
        System.out.println("TS2: "+msg2.getTS2().atZone(ZoneId.systemDefault()) );
        byte[] autenticador_c = Cifra.criaAUtenticador(msg2.getKcTgs(), cliente.getID_C(), cliente.getAD_C());
        saida.writeUTF("Servidor");                         // ID_V
        saida.writeInt(msg2.getTicket_tgs().length);        // tamanho do Ticket_tgs
        saida.write(msg2.getTicket_tgs());                  // Ticket_tgs (opaco, cifrado com K_tgs)
        saida.writeInt(autenticador_c.length);              // tamanho do Authenticator_c
        saida.write(autenticador_c);                        // E(K_c,tgs, [ID_C ‖ AD_C ‖ TS])
        saida.flush();
        System.out.println("mensagem (3) enviada com sucesso!");
    }
}