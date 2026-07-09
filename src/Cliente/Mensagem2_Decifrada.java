package Cliente;

import java.time.LocalDateTime;

public class Mensagem2_Decifrada {
    private byte[] ticket_tgs;
    private byte[] kcTgs;
    private LocalDateTime TS2;

    public byte[] getTicket_tgs() {
        return ticket_tgs;
    }

    public void setTicket_tgs(byte[] ticket_tgs) {
        this.ticket_tgs = ticket_tgs;
    }

    public byte[] getKcTgs() {
        return kcTgs;
    }

    public void setKcTgs(byte[] kcTgs) {
        this.kcTgs = kcTgs;
    }

    public LocalDateTime getTS2() {
        return TS2;
    }

    public void setTS2(LocalDateTime TS2) {
        this.TS2 = TS2;
    }
}
