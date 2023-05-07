import java.util.Hashtable;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;

import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;

import java.security.SecureRandom;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.MessageDigest;





public class Certification {
    public void run() {
        try {
           
        //Generation de la paire de clé publique et secrete coté utilisateur
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        PublicKey pk = kp.getPublic();
        PrivateKey sk = kp.getPrivate();
        //Enregistrer les keys ? voir tuto sur : https://www.novixys.com/blog/how-to-generate-rsa-keys-java/
        //System.out.println("Clé publique entre Utilisateur et Issuer  Pk(U,I) est : " +pk);


        //A faire : identité numérique ETH contract adress, verifier identité grace au Protocole de Schnorr
        String DID= "0x71C7656EC7ab88b098defB751B7401B5f6d8976F";
        System.out.println("Utilisateur authentifié en tant que propriétaire de l'identité numérique DID(U,I)"); 


        String atts="J'ai obtenu mon Diplome de Master 2 en 2023"; //peut etre un .json pour les attributs ?
        
        
        
        //Random r et random salt securisé
        Random rand = new Random();
        int r = rand.nextInt(); 
        //System.out.println("Random choisi est :" +r); 


        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        //System.out.println("Salt choisi est :"+salt); 



        /// ***CALCUL DE SIGMA σ *** ///
        
        //Creating a Signature object
        Signature sign = Signature.getInstance("SHA512withRSA");//seul algo qui marche ?
        //Initialize the signature
        sign.initSign(sk);
        //Concatener pk,atts,r
        String cert=pk+atts+r;  
        byte[] bytes = cert.getBytes();      
        //Adding data to the signature
        sign.update(bytes);
        //Signature de cert avec sk
        byte[] sigma = sign.sign();
        //System.out.println("Sigma calculé:"+sigma); 

        /// *** Salted Hash des attributs certifiés *** ///
        MessageDigest md = MessageDigest.getInstance("SHA-512");//seul algo ??
        md.update(salt);
        byte[] salted_hash = md.digest(atts.getBytes());
        //System.out.println("Salted Hash est:"+salted_hash);     


        //Sauvegarde du tableau des valeurs pour l'émetteur (Issuer)
        //Sauvegarde du salted hash des attributs au lieu du salt pour eviter les attaques par brute force sur la BDD
        String[] columnIssuer = {"DID", "DID:pk(U,I)","r","Salted hash"};    
        Object[][] dataIssuer = {
            {DID, pk, r, salted_hash} //,
                            };
         JTable tableIssuer = new JTable(dataIssuer, columnIssuer);
         for(int row = 0; row < tableIssuer.getRowCount(); row++) {

        for(int column = 0; column < tableIssuer.getColumnCount(); column++) {
            System.out.print(tableIssuer.getColumnName(column) + ": ");
            System.out.println(tableIssuer.getValueAt(row, column));
        }
        System.out.println(""); // Add line space
    }

        
        //Sauvegarde du tableau des valeurs pour l'émetteur (Issuer)
        String[] columnUser = {"Sigma σ", "r","Attributs","salt"};    
        Object[][] dataUser = {
            {sigma, r, atts, salt} //,
                            };
        JTable tableUser = new JTable(dataUser, columnUser);
        for(int rowu = 0; rowu < tableUser.getRowCount(); rowu++) {

        for(int column = 0; column < tableUser.getColumnCount(); column++) {
            System.out.print(tableUser.getColumnName(column) + ": ");
            System.out.println(tableUser.getValueAt(rowu, column));
        }
        System.out.println(""); // Add line space
    }



        /* révocation des informations d'identification sur demande de l'utilisateur

        DefaultTableModel dtm = new DefaultTableModel(dataIssuer, columnIssuer);
        tableIssuer = new JTable(dtm);
        Key searchedId = pk;//ID of the product to remove from the table
        int row = -1;//index of row or -1 if not found

        //search for the row based on the ID in the first column
        for(int i=0;i<dtm.getRowCount();++i) {
            if(dtm.getValueAt(i, 1).equals(searchedId))
            {
                row = i;
                break;
            }

            if(row != -1)
            dtm.removeRow(row);//remove row

        }   */

        

        /* Presentaton des idnetifiants au parti de confiance RP */
        //A faire : identité numérique ETH contract adress, verifier identité grace au Protocole de Schnorr
        String DIDRP= "0x71C7656EC7ab88b098defB751B7401B5f6d8976B";
        System.out.println("Utilisateur authentifié en tant que propriétaire de l'identité numérique DID(U,RP)"); 
        //Calcul du pseudonyme et envoie a RP
        Hashtable<Integer, String>
        pseudonym = new Hashtable<Integer, String>();
        pseudonym.put(r, DIDRP);

        //Verification du Sigma
        sign.initVerify(kp.getPublic());
        sign.update(bytes);
        boolean bool = sign.verify(sigma);
        if(bool) {
            System.out.println("Signature verified");   
         } else {
            System.out.println("Signature failed");
         }

         //Ou verification du h
        

        /*Verification du pseudonyme
        Hashtable<Integer, String>
        pseudonym = new Hashtable<Integer, String>();
        pseudonym.put(r, DIDRP); 
        if(pseudonym==pseudonym) {
            System.out.println("Pseudo verified");   
         } else {
            System.out.println("Pseudo failed");
         }*/



         //**Schnorr pour verifier la paire de clés**
        // create a challenge
        byte[] challenge = new byte[10000];
        ThreadLocalRandom.current().nextBytes(challenge);

        // sign using the private key
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(sk);
        sig.update(challenge);
        byte[] signature = sig.sign();

        // verify signature using the public key
        sig.initVerify(pk);
        sig.update(challenge);

        boolean keyPairMatches = sig.verify(signature); 
        if(keyPairMatches) {
            System.out.println("Paire verified");   
         } else {
            System.out.println("Paire failed");
         }

         //Verify that claim is atts, ZKP ? //





         








    
        








         }
        catch (NoSuchAlgorithmException e) {
            System.err.println("No such Algorithm");
            
        }
        catch (InvalidKeyException e) {
            System.err.println("Invalid key ");
            
        }
        catch (SignatureException e) {
            System.err.println("Invalid signature");
            
        }

    }

    public static void main(String[] args) {
        Certification srv = new Certification();
            srv.run();
      }
}
