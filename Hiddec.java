import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Hiddec 
{

    public static void main(String[] args) 
    {
        String keyHex = null;
        String ctrHex = null;
        String inputFile = null;
        String outputFile = null;

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
            else if (arg.startsWith("--input=")) 
            {
                inputFile = arg.substring(8);
            } 
            else if (arg.startsWith("--output=")) 
            {
                outputFile = arg.substring(9);
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

        try 
        {
            byte[] key = hexStringToByteArray(keyHex);
            byte[] iv = (ctrHex != null) ? hexStringToByteArray(ctrHex) : null;

            byte[] containerData = Files.readAllBytes(Paths.get(inputFile));

            byte[] decryptedData = decryptAndExtract(containerData, key, iv);

            if (decryptedData == null) 
            {
                System.err.println("Could not find or verify the hidden data.");
                System.exit(1);
            }

            try (FileOutputStream fos = new FileOutputStream(outputFile)) 
            {
                fos.write(decryptedData);
            }
            System.out.println("Successfully extracted and decrypted data to " + outputFile);

        } 
        catch (Exception e) 
        {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static byte[] decryptAndExtract(byte[] containerData, byte[] key, byte[] iv) throws Exception 
    {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] hKey = md5.digest(key);
        int blockSize = 16; //AES block size in bytes

        Cipher cipher;
        String transformation;
        boolean isCtrMode = (iv != null);

        if (isCtrMode) 
        {
            transformation = "AES/CTR/NoPadding";
            cipher = Cipher.getInstance(transformation);
        } 
        else 
        {
            transformation = "AES/ECB/NoPadding";
            cipher = Cipher.getInstance(transformation);
        }
        
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        // Scan for H(k)
        for (int i = 0; i <= containerData.length - blockSize; i += blockSize) 
        {
            if (isCtrMode) 
            {
                //For CTR, we need to re-initialize cipher for each starting position
                //to reset the counter effectively for that segment.
                //The IV for the first block of a potential blob is the original IV.
                //Subsequent blocks use incremented IV.
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv));
                //We can decrypt the whole container with a sliding window approach.
                //For each possible start offset of the blob:
                //Decrypt from this offset onwards, assuming it's the start of the blob.
                //Then search for H(k) in this decrypted stream.

                byte[] tempContainer = Arrays.copyOfRange(containerData, i, containerData.length);
                byte[] currentIv = Arrays.copyOf(iv, iv.length);
                Cipher scanCipher = Cipher.getInstance("AES/CTR/NoPadding");
                scanCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(currentIv));
                
                byte[] firstDecryptedBlock = scanCipher.update(Arrays.copyOfRange(tempContainer, 0, Math.min(blockSize, tempContainer.length)));
                if (firstDecryptedBlock != null && firstDecryptedBlock.length >= blockSize && Arrays.equals(Arrays.copyOf(firstDecryptedBlock, blockSize), hKey)) 
                {
                    //Found potential start H(k)
                    //Now try to find the rest of the blob
                    //Re-initialize cipher for actual blob decryption from this point
                    Cipher blobCipher = Cipher.getInstance("AES/CTR/NoPadding");
                    blobCipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(iv)); // IV for the start of blob
                    
                    //Now we can decrypt the rest of the container from offset i
                    byte[] fullDecryptedSegment = blobCipher.doFinal(Arrays.copyOfRange(containerData, i, containerData.length));


                    int dataStartOffset = blockSize; //H(k) found
                    int hKey2Offset = -1;

                    for (int j = dataStartOffset; j <= fullDecryptedSegment.length - blockSize; j += blockSize) 
                    {
                        if (Arrays.equals(Arrays.copyOfRange(fullDecryptedSegment, j, j + blockSize), hKey)) 
                        {
                            hKey2Offset = j;
                            break;
                        }
                    }

                    if (hKey2Offset != -1) 
                    {
                        int dataEndOffset = hKey2Offset;
                        int hDataOffset = hKey2Offset + blockSize;

                        if (hDataOffset + blockSize <= fullDecryptedSegment.length) 
                        {
                            byte[] data = Arrays.copyOfRange(fullDecryptedSegment, dataStartOffset, dataEndOffset);
                            byte[] hDataFromFile = Arrays.copyOfRange(fullDecryptedSegment, hDataOffset, hDataOffset + blockSize);
                            byte[] calculatedHData = md5.digest(data);

                            if (Arrays.equals(hDataFromFile, calculatedHData)) 
                            {
                                return data; //Successfully found and verified
                            }
                        }
                    }
                }
            } 
            else //Here is the logic for ECB Mode
            { 
                cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
                byte[] decryptedContainer = cipher.doFinal(containerData); //Decrypt whole container once

                for (int j = 0; j <= decryptedContainer.length - blockSize; j += blockSize) 
                {
                    if (Arrays.equals(Arrays.copyOfRange(decryptedContainer, j, j + blockSize), hKey)) 
                    {
                        //Found potential start H(k)
                        int dataStartOffset = j + blockSize;
                        int hKey2Offset = -1;

                        for (int k = dataStartOffset; k <= decryptedContainer.length - blockSize; k += blockSize) 
                        {
                            if (Arrays.equals(Arrays.copyOfRange(decryptedContainer, k, k + blockSize), hKey)) 
                            {
                                hKey2Offset = k;
                                break;
                            }
                        }

                        if (hKey2Offset != -1) 
                        {
                            int dataEndOffset = hKey2Offset;
                            int hDataOffset = hKey2Offset + blockSize;

                            if (hDataOffset + blockSize <= decryptedContainer.length) 
                            {
                                byte[] data = Arrays.copyOfRange(decryptedContainer, dataStartOffset, dataEndOffset);
                                byte[] hDataFromFile = Arrays.copyOfRange(decryptedContainer, hDataOffset, hDataOffset + blockSize);
                                byte[] calculatedHData = md5.digest(data);

                                if (Arrays.equals(hDataFromFile, calculatedHData)) 
                                {
                                    return data; //Successfully found and verified
                                } 
                                else 
                                {
                                     //Integrity check has failed, continue scanning
                                }
                            } 
                            else 
                            {
                                //Not enough data for H(Data), continue scanning
                            }
                        } 
                        else 
                        {
                             //No second H(k) found, continue scanning
                        }
                    }
                }
            }
        }
        return null; //Blob not found or verification failed
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
