package AutenticationServer;

import criptografia.FuncaoDerivacaoChave;

import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;

public class ASRepository {

    private final Map<String, byte[]> usuarioKDF = new HashMap<>();

    public ASRepository() {
        usuarioKDF.put("Pedro", hex("4a55d1afd0daa88d501e4b9957b2f7091e22fbcb579d6ba496eb3aafbfa0bf87"));
        usuarioKDF.put("TGS@TRABALHOSEC", hex("1a858ae2c624973b03ee23559f25b54cff6c92f3e66851c647860be1c73b231f"));
    }

    public byte[] obterKc(String principal) {
        byte[] kc = usuarioKDF.get(principal);
        return kc == null ? null : kc.clone();   // clone p/ proteger o interno
    }

    private static byte[] hex(String s) {
        return HexFormat.of().parseHex(s);
    }
    public byte[] find_K_C(String ID_C){
        return usuarioKDF.get(ID_C);
    }
}