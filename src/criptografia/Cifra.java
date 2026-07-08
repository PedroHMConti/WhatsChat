package criptografia;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Cifra {

    public static byte[] cifrar(byte[] chave, byte[] dados) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(chave, "AES"));
        return cipher.doFinal(dados);
    }

    public static byte[] decifrar(byte[] chave, byte[] pacote) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(chave, "AES"));
        return cipher.doFinal(pacote);
    }
}
