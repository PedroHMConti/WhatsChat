package TicketGrantingServer;

import java.net.InetAddress;
import java.time.LocalDateTime;

public class Autenticador {
    private String idc;
    private InetAddress adc;
    private LocalDateTime TS3;

    public String getIdc() {
        return idc;
    }

    public void setIdc(String idc) {
        this.idc = idc;
    }

    public InetAddress getAdc() {
        return adc;
    }

    public void setAdc(InetAddress adc) {
        this.adc = adc;
    }

    public LocalDateTime getTS3() {
        return TS3;
    }

    public void setTS3(LocalDateTime TS3) {
        this.TS3 = TS3;
    }
}
