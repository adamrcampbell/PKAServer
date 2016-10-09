/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package client;

import bean.Utility;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author Adam
 */
public class RSATest {
    
    public static void main(String[] args) {
    
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            
            ArrayList<byte[]> chunks = new ArrayList<>();
            byte[] keyBytes = publicKey.getEncoded();
            
            for(int i = 0; i < keyBytes.length;) {
                
                int difference = keyBytes.length - i;
                
                if(difference >= 100) {
                    byte[] chunk = new byte[100];
                    
                    for(int x = 0; x < 100; x++)
                        chunk[x] = keyBytes[i++];
                    
                    chunks.add(chunk);
                }
                else {
                    byte[] chunk = new byte[difference];
                    
                    for(int x = 0; x < difference; x++)
                        chunk[x] = keyBytes[i++];
                    
                    chunks.add(chunk);
                }
            }
            
            byte[] encryptedChunk = new byte[chunks.size() * 256]; 
            int counter = 0;
            
            // Encrypt chunks
            for(int i = 0; i < chunks.size(); i++) {
                // Get chunk i
                byte[] chunk = chunks.get(i);
                // Encrypt inner layer
                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding");
                rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
                byte[] inner = rsaCipher.doFinal(chunk);
                // Encrypt outer layer
                Cipher rsaCipher2 = Cipher.getInstance("RSA/ECB/NoPadding");
                rsaCipher2.init(Cipher.ENCRYPT_MODE, privateKey);
                byte[] outer = rsaCipher2.doFinal(inner);
                
                for(int x = 0; x < outer.length; x++)
                        encryptedChunk[counter++] = outer[x];
            }
            
            System.out.println("Shiz: " + encryptedChunk.length);
                
            String base64 = Utility.encodeToBase64(encryptedChunk);
                
            System.out.println("Base Shit: " + base64);
            
            String toBase = "";
            
            System.out.println("Encrypted/Encoded: " + toBase);
            
            byte[] fromBase = Base64.getDecoder().decode(toBase);
            
            Cipher rsaCipher3 = Cipher.getInstance("RSA/ECB/NoPadding");
            rsaCipher3.init(Cipher.DECRYPT_MODE, publicKey);
            byte[] outer2 = rsaCipher3.doFinal(fromBase);
            
            Cipher rsaCipher4 = Cipher.getInstance("RSA/ECB/NoPadding");
            rsaCipher4.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] result = rsaCipher4.doFinal(outer2);
            
            System.out.println("Result: " + new String(result));
            
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSATest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(RSATest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(RSATest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(RSATest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(RSATest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
