package assinaturadigital;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.*;
import java.util.Base64;

import static java.nio.charset.StandardCharsets.UTF_8;

public class AssinaturaTXT {
    
    public static void main(String args[]) throws Exception {
        
        final String nomeKeyStore = "mykey";
        final String senhaKeyStore = "store123";
        final String senhaPrivateKey = "key123";
        final String nomeCertificado = "mykey";
        
        // Gera o par de chaves
        KeyPair pair = generateKeyPair();
        
        // Pega o par de chaves da KeyStore
        // KeyPair pair = getKeyPairFromKeyStore(nomeKeyStore, senhaKeyStore, senhaPrivateKey, nomeCertificado);

        // Define a mensagem 
        //String mensagem = "Teste para assinatura digital em TXT";
        //System.out.println("Texto original: " + mensagem);
        
        // Ler mensagem do arquivo
        AssinaturaTXT assD = new AssinaturaTXT();
        String mensagem = assD.lerArquivo();
        
        // Criptografa a mensagem
        String TextoCifrado = criptografa(mensagem, pair.getPublic());
        System.out.println("Texto Criptografado: " + TextoCifrado);
        
        // Descriptografa a mensagem
        String MensagemDescifrada = descriptografa(TextoCifrado, pair.getPrivate());
        System.out.println("Texto Descriptografado: " + MensagemDescifrada);

        // Assina digitalmente a mensagem
        String assinatura = assinatxt(TextoCifrado, pair.getPrivate());
        System.out.println("Assinatura: " + assinatura);

        // Verifica a assinatura
        boolean valido = verificaAssinatura(TextoCifrado, assinatura, pair.getPublic());
        System.out.println("Assinatura Válida? " + valido);
        
        // Cria o arquivo assinado
        assD.criaArquivo(mensagem, assinatura);
    }
    
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, new SecureRandom());
        KeyPair pair = generator.generateKeyPair();

        return pair;
    }

    public static KeyPair getKeyPairFromKeyStore(String nomeKeyStore, 
        String senhaKeyStore, String senhaPrivateKey, String nomeCertificado) throws Exception {
        // Par de chaves gerada com o comando:
        // keytool -genkeypair -alias mykey -storepass store123 -keypass key123 -keyalg RSA -keystore keystore.jks

        InputStream ins = AssinaturaTXT.class.getResourceAsStream("/keystore.jks");

        KeyStore keyStore = KeyStore.getInstance("JCEKS");
        keyStore.load(ins, senhaKeyStore.toCharArray());
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection(senhaPrivateKey.toCharArray()); 
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(nomeCertificado, keyPassword);
        java.security.cert.Certificate cert = keyStore.getCertificate(nomeCertificado); 
        PublicKey publicKey = cert.getPublicKey();
        PrivateKey privateKey = privateKeyEntry.getPrivateKey();

        return new KeyPair(publicKey, privateKey);
    }

    public static String criptografa(String mensagem, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] TextoCifrado = encryptCipher.doFinal(mensagem.getBytes(UTF_8));

        return Base64.getEncoder().encodeToString(TextoCifrado);
    }

    public static String descriptografa(String TextoCifrado, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(TextoCifrado);
        Cipher decriptCipher = Cipher.getInstance("RSA");
        decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decriptCipher.doFinal(bytes), UTF_8);
    }

    public static String assinatxt(String TextoCifrado, PrivateKey privateKey) throws Exception {
        Signature assina = Signature.getInstance("SHA256withRSA");
        assina.initSign(privateKey);
        assina.update(TextoCifrado.getBytes(UTF_8));
        byte[] assinatura = assina.sign();

        return Base64.getEncoder().encodeToString(assinatura);
    }

    public static boolean verificaAssinatura(String TextoCifrado, String assinatura, PublicKey publicKey) throws Exception {
        Signature verifica = Signature.getInstance("SHA256withRSA");
        verifica.initVerify(publicKey);
        verifica.update(TextoCifrado.getBytes(UTF_8));
        byte[] signatureBytes = Base64.getDecoder().decode(assinatura);

        return verifica.verify(signatureBytes);
    }
    
    public String lerArquivo() throws FileNotFoundException, IOException{
        String mensagem = "";
        
        try {
            FileReader arquivo = new FileReader("src/arquivos/teste.txt");
            BufferedReader br = new BufferedReader(arquivo);
            while(br.ready()){
                mensagem += br.readLine();
            } 
        }catch(IOException e){
            System.err.printf("Erro na abertura do arquivo: %s.\n",
            e.getMessage());
        }
        System.out.println(mensagem);
        return mensagem;
    }
    
    public void criaArquivo(String mensagem, String assinatura) throws FileNotFoundException, IOException{
        String inicioAssinatura = "\r\n\n------------------BEGIN SIGNATURE-----------------\r\n\n";
	String finalAssinatura = "\r\n\n-------------------END SIGNATURE------------------";
        
        try (
            FileOutputStream out = new FileOutputStream("src/arquivos/testeAssinado.txt")) {
            out.write(mensagem.getBytes(), 0, mensagem.length());
            out.write(inicioAssinatura.getBytes(), 0, inicioAssinatura.length());
            int count = 0;
            int ler = 0;
            String linha = "\n";
            for (int i=0; i <= assinatura.length(); i++){    
                if (count == 50){
                    out.write(assinatura.getBytes(), ler, count);
                    out.write(linha.getBytes());
                    count = 0;
                    ler = ler + 50;
                }if (i == assinatura.length()){
                    out.write(assinatura.getBytes(), ler, count);
                }else{
                    count++;
                }    
            }    
            out.write(finalAssinatura.getBytes(), 0, finalAssinatura.length());
        }
    }    
}