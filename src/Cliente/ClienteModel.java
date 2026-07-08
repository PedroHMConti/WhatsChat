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

    public ClienteModel(String ID_C,String ID_tgs,String senha) throws Exception {
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
