package TicketGrantingServer;

public class TgsModel {

    private byte[] k_c_tgs;

    public byte[] getK_c_tgs() {
        return k_c_tgs;
    }

    public void setK_c_tgs(byte[] k_c_tgs) {
        this.k_c_tgs = k_c_tgs;
    }

    //identificacao do tgs
    private String ID_tgs;

    private String senha;

    public String getID_tgs() {
        return ID_tgs;
    }

    public void setID_tgs(String ID_tgs) {
        this.ID_tgs = ID_tgs;
    }

    public String getSenha() {
        return senha;
    }

    public void setSenha(String senha) {
        this.senha = senha;
    }

    public TgsModel(String ID_tgs, String senha) {
        this.ID_tgs = ID_tgs;
        this.senha = senha;
    }
}
