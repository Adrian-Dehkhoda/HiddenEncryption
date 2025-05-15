import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Hidenc
{
    private static final int AES_BLOCK_SIZE = 16; //Bytes

    public static void main(String[] args) 
    {
        String keyHex = null;
        String ctrHex = null;
        Long offset = null;
        String inputFile = null;
        String outputFile = null;
        String templateFile = null;
        Integer size = null;

        for (String arg : args) //I'm a spagetti coder leave me alone
        {
            if (arg.startsWith("--key=")) 
            {
                keyHex = arg.substring(6);
            } 
            else if (arg.startsWith("--ctr=")) 
            {
                ctrHex = arg.substring(6);
            } 
            else if (arg.startsWith("--offset=")) 
            {
                offset = Long.parseLong(arg.substring(9));
            } 
            else if (arg.startsWith("--input=")) 
            {
                inputFile = arg.substring(8);
            } 
            else if (arg.startsWith("--output=")) 
            {
                outputFile = arg.substring(9);
            } 
            else if (arg.startsWith("--template=")) 
            {
                templateFile = arg.substring(11);
            } 
            else if (arg.startsWith("--size=")) 
            {
                size = Integer.parseInt(arg.substring(7));
            } 
            else 
            {
                System.err.println("Unknown argument: " + arg);
                System.exit(1);
            }
        }

        if (keyHex == null || inputFile == null || outputFile == null) 
        {
            System.err.println("Missing required arguments. Required: --key, --input, --output");
            System.exit(1);
        }
        if (templateFile != null && size != null) 
        {
            System.err.println("Cannot specify both --template and --size.");
            System.exit(1);
        }
        if (templateFile == null && size == null) 
        {
            System.err.println("Must specify either --template or --size.");
            System.exit(1);
        }

        try 
        {
            byte[] key = hexStringToByteArray(keyHex);
            byte[] iv = (ctrHex != null) ? hexStringToByteArray(ctrHex) : null;
            byte[] dataToHide = Files.readAllBytes(Paths.get(inputFile));

            //Create the blob
            byte[] blob = createBlob(dataToHide, key, iv);

            byte[] containerData;

            if (templateFile != null) 
            {
                containerData = Files.readAllBytes(Paths.get(templateFile));
            } 
            else 
            { 
                containerData = new byte[size];
                new SecureRandom().nextBytes(containerData); //Fill with random data
            }

            long actualOffset;
            if (offset == null) 
            {
                if (containerData.length - blob.length < 0) 
                {
                    System.err.println("Error: Blob is larger than the container size.");
                    System.exit(1);
                }
                //Ensure offset is block aligned if possible. For simplicity, let's make it truly random within possible bounds.
                actualOffset = new Random().nextInt(containerData.length - blob.length + 1);
            } 
            else 
            {
                actualOffset = offset;
            }
            
            if (actualOffset < 0 || actualOffset + blob.length > containerData.length) 
            {
                System.err.println("Error: Offset is out of bounds or blob does not fit at the specified offset.");
                System.exit(1);
            }

            //Embed blob into container
            System.arraycopy(blob, 0, containerData, (int) actualOffset, blob.length);

            try (FileOutputStream fos = new FileOutputStream(outputFile)) 
            {
                fos.write(containerData);
            }
            System.out.println("Successfully created and hid data in " + outputFile);

        } 
        catch (Exception e) 
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static byte[] createBlob(byte[] data, byte[] key, byte[] iv) throws Exception 
    {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] hKey = md5.digest(key);
        byte[] hData = md5.digest(data);

        //Construct plaintext blob: H(k) + Data + H(k) + H(Data)
        //Ensure data length is multiple of block size for simplicity, or handle padding if not.
        //The problem statement implies we don't need to worry about padding for Data itself.
        //However, the total blob must be a multiple of block size for ECB/CTR without padding.
        
        int dataLength = data.length;
        //The problem states "the hidden information is aligned on block boundaries" and "container files consist of an integer number of AES blocks".
        //This implies Data itself might not be block aligned, but the blob placed in the container will be.
        //The encryption will handle the overall blob. Let's ensure the plaintext blob is block-aligned before encryption.

        int plainBlobLength = hKey.length + dataLength + hKey.length + hData.length;
        int paddingLength = 0;

        if (plainBlobLength % AES_BLOCK_SIZE != 0) 
        {
            paddingLength = AES_BLOCK_SIZE - (plainBlobLength % AES_BLOCK_SIZE);
        }
        
        byte[] plainBlob = new byte[plainBlobLength + paddingLength];
        System.arraycopy(hKey, 0, plainBlob, 0, hKey.length);
        System.arraycopy(data, 0, plainBlob, hKey.length, data.length);
        System.arraycopy(hKey, 0, plainBlob, hKey.length + data.length, hKey.length);
        System.arraycopy(hData, 0, plainBlob, hKey.length + data.length + hKey.length, hData.length);
        //Padding bytes are already zero, which is fine.

        Cipher cipher;
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
        String transformation;

        if (iv != null) //CTR mode
        { 
            transformation = "AES/CTR/NoPadding";
            cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
        } 
        else //ECB mode
        { 
            transformation = "AES/ECB/NoPadding";
            cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        }
        
        return cipher.doFinal(plainBlob);
    }

    public static byte[] hexStringToByteArray(String s) { /*Simple hex to bytes conversion, modified. Original: https://codingtechroom.com/question/convert-hex-string-to-byte-array-java, 
        I would put this in a utilities class but I don't want to risk compromising the integrity of the file structure*/
        if (s == null || s.length() % 2 != 0) 
        {
            throw new IllegalArgumentException("Hex string must have an even number of characters and not be null.");
        }
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + 
                                Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
