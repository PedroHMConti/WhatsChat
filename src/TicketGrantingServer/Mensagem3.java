package TicketGrantingServer;

public class Mensagem3 {
    private String ID_V;
    private byte[] ticket_tgs;
    private byte[] authenticator_c;

    public Mensagem3(String ID_V, byte[] ticket_tgs, byte[] authenticator_c) {
        this.ID_V = ID_V;
        this.ticket_tgs = ticket_tgs;
        this.authenticator_c = authenticator_c;
    }

    public String getID_V() {
        return ID_V;
    }

    public void setID_V(String ID_V) {
        this.ID_V = ID_V;
    }

    public byte[] getTicket_tgs() {
        return ticket_tgs;
    }

    public void setTicket_tgs(byte[] ticket_tgs) {
        this.ticket_tgs = ticket_tgs;
    }

    public byte[] getAuthenticator_c() {
        return authenticator_c;
    }

    public void setAuthenticator_c(byte[] authenticator_c) {
        this.authenticator_c = authenticator_c;
    }
}
