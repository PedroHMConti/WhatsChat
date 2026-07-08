package criptografia;//funcao de derivacao de chave

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public class FuncaoDerivacaoChave {

    public static byte[] derivarChave(String senha, String salt) throws Exception {

        //funcao do java que implementa hash
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // concatena senha + salt
        byte[] atual = (senha + salt).getBytes(StandardCharsets.UTF_8);

        // aplica o hash iterativamente
        for (int i = 0; i < 100; i++) {
            atual = md.digest(atual);   // digest() já reseta o MessageDigest
        }

        return atual; // 32 bytes (SHA-256) — pode truncar p/ o tamanho da cifra
    }
}
