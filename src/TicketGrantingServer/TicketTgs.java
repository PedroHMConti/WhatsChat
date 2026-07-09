package TicketGrantingServer;

import java.net.InetAddress;
import java.time.LocalDateTime;

public class TicketTgs {
    private byte[] k_c_tgs;
    private String ID_C;
    private InetAddress AD_C;
    private LocalDateTime TS2;

    public byte[] getK_c_tgs() {
        return k_c_tgs;
    }

    public void setK_c_tgs(byte[] k_c_tgs) {
        this.k_c_tgs = k_c_tgs;
    }

    public String getID_C() {
        return ID_C;
    }

    public void setID_C(String ID_C) {
        this.ID_C = ID_C;
    }

    public InetAddress getAD_C() {
        return AD_C;
    }

    public void setAD_C(InetAddress AD_C) {
        this.AD_C = AD_C;
    }

    public LocalDateTime getTS2() {
        return TS2;
    }

    public void setTS2(LocalDateTime TS2) {
        this.TS2 = TS2;
    }
}
