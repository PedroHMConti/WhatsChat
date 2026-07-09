package Cliente;
import criptografia.FuncaoDerivacaoChave; // ajuste conforme seu pacote real

import java.net.InetAddress;

public class ClienteModel {
    ;

    //Identificacao do cliente
    private String ID_C;

    //endereco do cliente
    private final InetAddress AD_C = InetAddress.getLoopbackAddress();

    //tgs desejado
    private String ID_tgs;

    private String senha;

    private byte[] k_c;

    private byte[] k_cTgs;

    public byte[] getK_c() {
        return k_c;
    }

    public void setK_c(byte[] k_c) {
        this.k_c = k_c;
    }

    public byte[] getK_cTgs() {
        return k_cTgs;
    }

    public void setK_cTgs(byte[] k_cTgs) {
        this.k_cTgs = k_cTgs;
    }

    public ClienteModel(String ID_C, String ID_tgs, String senha) throws Exception {
        this.ID_C = ID_C;
        this.ID_tgs = ID_tgs;
        this.senha = senha;
        this.k_c = FuncaoDerivacaoChave.derivarChave(senha, "unb.br");
    }

    @Override
    public String toString() {
        return "ClienteModel{" +
                "ID_C='" + ID_C + '\'' +
                ", AD_C=" + AD_C +
                ", ID_tgs='" + ID_tgs + '\'' +
                '}';
    }

    public String getID_C() {
        return ID_C;
    }

    public void setID_C(String ID_C) {
        this.ID_C = ID_C;
    }

    public String getID_tgs() {
        return ID_tgs;
    }

    public void setID_tgs(String ID_tgs) {
        this.ID_tgs = ID_tgs;
    }

    public InetAddress getAD_C() {
        return AD_C;
    }
}
