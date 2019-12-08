package assinaturadigital;

import static assinaturadigital.AssinaturaTXT.assinatxt;
import static assinaturadigital.AssinaturaTXT.criptografa;
import static assinaturadigital.AssinaturaTXT.generateKeyPair;
import static assinaturadigital.AssinaturaTXT.verificaAssinatura;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.KeyPair;

public class AssinaturaDigital {

    public static void main(String[] args) throws IOException, Exception {
        
        final String localDocumento = "src/arquivos/purchaseOrder.xml";
        final String localKeystore = "src/arquivos/keystore";
        final String senhaKeystore = "changeit";
        final String nomePrivateKey = "mykey";
        final String senhaPrivateKey = "changeit";
        final String localDocumentoAssinado = "src/arquivos/signedPurchaseOrder.xml";
        final Writer xmlAssinado = new FileWriter("src/arquivos/signedPurchaseOrder.xml");  
        
        AssinaturaXML signxml = new AssinaturaXML();
        signxml.assinar(localDocumento, localKeystore, senhaKeystore, nomePrivateKey, senhaPrivateKey, localDocumentoAssinado);
        //sign.assinarTag(localDocumento, localKeystore, senhaKeystore, nomePrivateKey, senhaPrivateKey, localDocumentoAssinado, xmlAssinado, "Buyer");
             
        KeyPair pair = generateKeyPair();
        
        AssinaturaTXT assD = new AssinaturaTXT();
        String mensagem = assD.lerArquivo();
    
        String TextoCifrado = criptografa(mensagem, pair.getPublic());
        String assinatura = assinatxt(TextoCifrado, pair.getPrivate());
        
        boolean valido = verificaAssinatura(TextoCifrado, assinatura, pair.getPublic());
        System.out.println("Assinatura Válida? " + valido); 
        assD.criaArquivo(mensagem, assinatura);
    }   
}
