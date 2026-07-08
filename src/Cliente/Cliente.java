package Cliente;

import criptografia.Cifra;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.HexFormat;

import static criptografia.Cifra.decifrar;
import static criptografia.FuncaoDerivacaoChave.derivarChave;

public class Cliente {
    public static void main(String[] args) throws Exception {
        ClienteModel cliente = new ClienteModel("Pedro", "TGS@TRABALHOSEC", "senha");

        // ===== FASE (a): troca com o AS =====
        byte[] ticketTgs;
        byte[] kcTgs;
        try (Socket socketAS = new Socket("localhost", 4999);
             var saida   = new DataOutputStream(socketAS.getOutputStream());
             var entrada = new DataInputStream(socketAS.getInputStream())) {

            // mensagem (1): ID_C ‖ ID_tgs ‖ TS1
            System.out.println("fase (a) informando mensagem (1): ID_C ‖ ID_tgs ‖ TS1");
            System.out.println("ID_C: " + cliente.getID_C());
            System.out.println("ID_tgs: " + cliente.getID_tgs());
            System.out.println("TS1: "+System.currentTimeMillis() );
            saida.writeUTF(cliente.getID_C());
            saida.writeUTF(cliente.getID_tgs());
            saida.writeLong(System.currentTimeMillis());
            saida.flush();
            System.out.println("saída enviada");

            // mensagem (2): E(K_c, [K_c,tgs ‖ ID_tgs ‖ TS2 ‖ Ticket_tgs])  — LER
            System.out.println("Recebe mensagem (2): E(K_c, [K_c,tgs ‖ ID_tgs ‖ TS2 ‖ Ticket_tgs]) ");
            // ── deriva K_c (tem que dar a MESMA chave que o AS usou) ──
            byte[] kc = derivarChave("senha", "unb.br");
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
            kcTgs = new byte[tamKcTgs];
            dis.readFully(kcTgs);
            // 3. writeUTF(idTgs)         →  readUTF
            String idTgs = dis.readUTF();
            // 4. writeLong(ts2)          →  readLong
            long ts2 = dis.readLong();
            // 5. writeInt(ticketTgs.length) → readInt
            int tamTicket = dis.readInt();
            // 6. write(ticketTgs)        →  readFully
            ticketTgs = new byte[tamTicket];
            dis.readFully(ticketTgs);   // bloco opaco — cifrado com K_tgs, guarda p/ a fase (b)

            System.out.println("K_c,tgs recebida: " + HexFormat.of().formatHex(kcTgs));
            System.out.println("ID_tgs: " + idTgs);
            System.out.println("Ticket_tgs (opaco, " + tamTicket + " bytes) guardado.");

        } catch (Exception e) {
            e.printStackTrace();
        }

        // ===== FASE (b): agora sim conecta ao TGS, usando ticketTgs =====
        // try (Socket socketTGS = new Socket("localhost", 4998)) { ... }

        // ===== FASE (c): depois conecta ao serviço, usando ticketV =====
    }
}