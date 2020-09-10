/*
CS-421 Computer Networks - Simple Social Network
Coders: Hamza Pehlivan - Şeyma Aybüke Ertekin
*/
import java.io.DataOutputStream;
import java.io.InputStream;
import java.net.Socket;
import java.nio.ByteBuffer;

public class SecureClient{

    static Socket mySocket = null;
    static DataOutputStream outToServer = null;


    //This method gets a response message from the server and returns the data part of the message.
    public static byte[] getResponseMessage() {
        byte[] data = null;
        try{
            InputStream in = mySocket.getInputStream();

            //read type
            byte [] type = new byte[8];
            in.read(type, 0, 8);

            //read length
            byte[] bLength = new byte[4];
            in.read(bLength, 0, 4);

            //convert byte array to integer
            ByteBuffer wrapped = ByteBuffer.wrap(bLength);
            int length = wrapped.getInt();

            //read data
            data = new byte[length];
            in.read(data, 0, length);
        }
        catch(Exception e){
            e.printStackTrace();
        }

        return data;
    }

    //This method merges two byte arrays and returns joint array.
    public static byte[] concatBytes(byte[] first, byte[] second){
        int len1 = first.length;
        int len2 = second.length;
        byte[] result = new byte[len1 + len2];

        System.arraycopy(first, 0, result, 0, len1);
        System.arraycopy(second, 0, result, len1, len2);
        return result;
    }

    public static void main(String[] args){

        String addr = "127.0.0.1";

        //If no port number is given as an input, return.
        if(args.length < 1)
            return;

        int controlPort = Integer.parseInt(args[0]);

        try {
            /*
                Part 1 - HANDSHAKE
            */
            CryptoHelper crypto = new CryptoHelper();   //Create an instance of helper class
            byte[] pk = new byte[8];                    //Public key of server
            boolean verified = false;                   //If server is verified or not.
            do{
                //Initialize socket and output stream
                mySocket = new Socket(addr, controlPort);
                outToServer = new DataOutputStream(mySocket.getOutputStream());

                //Send hello message to server
                outToServer.write(concatBytes("HELLOxxx".getBytes(), ByteBuffer.allocate(4).putInt(0).array()));
                outToServer.flush();

                //Get certificate from server
                byte[] data = getResponseMessage();

                //Convert certificate to string
                String cert = new String(data);

                //If certificate is not empty
                if(cert != "") {

                    //Get CA from certificate string
                    String array[] = cert.split("CA=");
                    array = array[1].split("SIGNATURE=");
                    String ca = array[0];

                    //Get signature from certificate, last 8 bytes
                    byte signature[] = new byte[8];
                    for(int i = 0; i < 8; i++)
                        signature[i] = data[data.length - 8 + i];

                    //Get public key of the server which starts after PK= and it is 8 bytes long.
                    int j = 0;
                    for(int i = cert.indexOf("PK") + 3; j < 8; j++, i++)
                        pk[j] = data[i];

                    //Check certificate, signature, and CA to learn if the server is fake or not.
                    verified = crypto.verifySignature(data, signature, ca);
                }
            }while(!verified);

            //Generate a private key
            int secretKey = crypto.generateSecret();

            //Encrypt the private key
            byte[] encryptedKey = crypto.encryptSecretAsymmetric(secretKey, pk);

            //Send private key to the server
            outToServer.write(concatBytes(concatBytes("SECRETxx".getBytes(), ByteBuffer.allocate(4).putInt(encryptedKey.length).array()), encryptedKey));

            /*
                Part 2 - AUTHENTICATION
            */
            //Send STARTENC command to start to encrypt the data
            byte[] out = concatBytes("STARTENC".getBytes(), ByteBuffer.allocate(4).putInt(0).array());
            outToServer.write(out);
            outToServer.flush();

            //Create an authentication string and encrypt it with secret key
            String authentication = "bilkent cs421";
            byte [] authEncrypted = crypto.encryptSymmetric(authentication, secretKey);

            //Send encrypted authentication string to the server
            byte [] temp = concatBytes("AUTHxxxx".getBytes(),ByteBuffer.allocate(4).putInt(authEncrypted.length).array());
            out = concatBytes(temp, authEncrypted);
            outToServer.write(out);

            //Get response of the server and decrypt it.
            byte [] authResult = getResponseMessage();
            String authResultCheck = crypto.decryptSymmetric( authResult, secretKey);

            //Check if the authentication string is valid or not
            if (!authResultCheck.equals("OK")) {
                System.out.println("Invalid username or password!");
                System.exit(0);
            }
            System.out.println("Authentication Response: " + authResultCheck);

            //Send ENDEC command to the server to stop sending encrypted messages
            out = concatBytes("ENDENCxx".getBytes(), ByteBuffer.allocate(4).putInt(0).array());
            outToServer.write(out);
            outToServer.flush();

            /*
                Part 3 - VIEW PUBLIC POSTS
            */
            //Send PUBLIC command to the server to view the public posts
            outToServer.write(concatBytes("PUBLICxx".getBytes(), ByteBuffer.allocate(4).putInt(0).array()));
            outToServer.flush();

            //Get the response of the server and print public posts.
            String response = new String(getResponseMessage());
            System.out.println("Public Posts:");
            System.out.println(response);

            /*
                Part 4 - VIEW PRIVATE MESSAGES
            */
            //Send STARTENC command to start to encrypt the data
            outToServer.write(concatBytes("STARTENC".getBytes(), ByteBuffer.allocate(4).putInt(0).array()));
            outToServer.flush();

            //Send PRIVATE command in order to get private messages
            outToServer.write(concatBytes("PRIVATEx".getBytes(), ByteBuffer.allocate(4).putInt(0).array()));
            outToServer.flush();

            //Get private messages from the server, decrypt, and print them
            String privateMessage = crypto.decryptSymmetric(getResponseMessage(), secretKey);
            System.out.println("Private Messages:");
            System.out.println(privateMessage);

            //Send ENDEC command to the server to stop sending encrypted messages
            outToServer.write(concatBytes("ENDENCxx".getBytes(), ByteBuffer.allocate(4).putInt(0).array()));
            outToServer.flush();

            /*
                Part 5 - LOGOUT
            */
            //Send logout message to the server
            outToServer.write(concatBytes("LOGOUTxx".getBytes(), ByteBuffer.allocate(4).putInt(0).array()));

            //Close connections
            mySocket.close();
            outToServer.close();

        }
        catch(Exception e){
            e.printStackTrace();
        }
    }

}