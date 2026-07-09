package Cliente;

import java.time.LocalDateTime;

public class Mensagem4_Decifrada {
    private byte[] kcV;
    private String idV;
    private LocalDateTime ts4;
    private byte[] ticketV;

    public byte[] getKcV() {
        return kcV;
    }

    public void setKcV(byte[] kcV) {
        this.kcV = kcV;
    }

    public String getIdV() {
        return idV;
    }

    public void setIdV(String idV) {
        this.idV = idV;
    }

    public LocalDateTime getTs4() {
        return ts4;
    }

    public void setTs4(LocalDateTime ts4) {
        this.ts4 = ts4;
    }

    public byte[] getTicketV() {
        return ticketV;
    }

    public void setTicketV(byte[] ticketV) {
        this.ticketV = ticketV;
    }
}