package criptografia;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;

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
    public static byte[] criaAUtenticador(byte[] kcTgs, String idc, InetAddress adc) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(buf);
        dos.writeUTF(idc);                          // ID_C
        dos.writeUTF(adc.getHostAddress());         // AD_C
        dos.writeLong(System.currentTimeMillis());  // TS
        return cifrar(kcTgs, buf.toByteArray());    // E(K_c,tgs, [ID_C ‖ AD_C ‖ TS])
    }
}
