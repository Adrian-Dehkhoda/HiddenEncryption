# Introduction

In this lab you will gain insights into the problems of hidden encryption and plausible deniability. You will also get first-hand experience with tools and methods for symmetric-key encryption and decryption, and for cryptographic hashing.

The lab is about encrypting information and storing it in the file system on your computer. If you have sensitive information that you want to protect, you can put the information in a file and encrypt it. Most operating systems have easy-to-use tools for this.

There is a problem with this approach, though. The encrypted files are still visible in the computer. If an attacker gets access to a computer and finds an encrypted file, the attacker might be able to use methods of social engineering, threats, and so on, to get the decryption key from the computer’s owner and decrypt the information.

If the encrypted information instead is hidden somehow, it might be more difficult for the attacker to detect that it exists, and the computer’s owner could be able to deny the presence of encrypted information – this is called plausible deniability.

In this lab assignment, you will extract encrypted information hidden in files, and create files with hidden encrypted information in them.

# Hidden Encryption

The idea behind the way in which encrypted information is hidden in this assignment is that the encrypted information will be a “blob” of data that can be placed anywhere inside a file. To the attacker, the encrypted information appears as random data. For someone who knows what to look for, the blob is possible to locate and decrypt. The blob can then be stored in a suitable place in the file system: as data embedded somewhere in a binary file, such as an executable file, JPEG image, audio data, or in some unused parts of the file system (unallocated space on a disk drive, for instance).

The format of the the data “blob” is shown in the figure below (in blue). The entire blob is encrypted with a secret key k. The first element in the blob is the hash of the secret key, H(k). Then comes the information you want to hide, Data, followed by H(k) again. Last is another hash: the hash of Data, H(Data).

The basic principle here is that H(k), the hash of the secret key, marks the start and the end of the hidden information. The terminating hash H(Data) is for integrity protection.

The blob is placed somewhere inside a container file (the red parts). In other words, the blob is inserted at some position inside a file.

In order to locate and decrypt the hidden data in a container file, the following steps would be taken:

1. Compute H(k), the hash of the secret key k.
2. Scan the file, by decrypting with k and searching for H(k) in the decrypted data.
3. When H(k) is found, it indicates the start of the blob.
4. Decrypt the succeeding blocks until the next H(k) is found.
5. Take the plaintext between the two occurrences of H(k) as the secret information, Data.
6. Decrypt the block after the second H(k). Call this value H’.
7. Compute the hash of the data, H(Data).
8. Verify that H(Data) equals H’, in which case the operation has been successful and Data is the hidden information.

# Instructions

## Preliminaries

You will get a challenge with personalized data. Your individual challenge is available for you in your personal repository on KTH GitHub.

To solve this assignment, you will write to programs: Hidenc and Hiddec. They use AES with 128-bit keys to encrypt data and hide it inside a container file (Hidenc), and to extract and decrypt data that is hidden inside a container file (Hiddec). Two modes of operation for AES are supported: AES-128-ECB and AES-128-CTR.

The hashing algorithm to compute the hash of the key and the data is MD5.

## The Hiddec Program

Hiddec takes a container file as input, extracts a blob from it, and produces the decrypted data from the blob as output.

The program is compiled in the following way:

```
$ javac Hiddec.java
```

The program should take the following arguments (note that the arguments can be given in any order):

* `--key=KEY`  
  Use KEY for encryption key, given as a hexadecimal string.

* `--ctr=CTR`  
  Use CTR as the initial value for the counter in AES-128-CTR mode. Implies that AES-128-CTR mode should be used for encryption (otherwise AES-128-ECB). The counter given as a hexadecimal string.

* `--input=INPUT`  
  Input file. INPUT is the name of the container file.

* `--output=OUTPUT`  
  Output file. OUTPUT is the name of the file where the decrypted data should be stored. If the file does not exist, it will be created. If it exists already, its content is overwritten.

Example:

```
$ java Hiddec --key=$(<task1.key) --input=task1.data --output=file1.data
```

## The Hidenc Program

Hidenc creates a blob and embeds it into a container file. The program is compiled in the following way:

```
$ javac Hidenc.java
```

The program should take the following arguments (which can be given in any order):

* `--key=KEY`  
  Use KEY for encryption key, given as a hexadecimal string.

* `--ctr=CTR`  
  Use CTR as the initial value for the counter in AES-128-CTR mode.

* `--offset=NUM`  
  Place the blob in the file at an offset of NUM bytes into the container file. If no offset is given, Hidenc generates it by random.

* `--input=INPUT`  
  INPUT is the name of the file with the data that should be used as the data portion of the blob.

* `--output=OUTPUT`  
  OUTPUT is the name of the file where the container with the final result is stored.

* `--template=TEMPLATE`  
  Use the file named TEMPLATE as a template for the container in which the blob should be stored.

* `--size=SIZE`  
  The total size of the output file should be SIZE bytes.

# Task 1

Use your Hiddec program for this:

```
$ java Hiddec --key=$(<task1.key) --input=task1.data --output=file1.data
```

# Task 2

Use your Hidenc program for this:

```
$ java Hidenc --key=$(<task2.key) --offset=$(<task2.offset) --input=task2.data --output=file2.data --size=2048
```

# Task 3

Use your Hiddec program for this:

```
$ java Hiddec --key=$(<task3.key) --ctr=$(<task3.ctr) --input=task3.data --output=file3.data
```

# Task 4

Use your Hidenc program for this:

```
$ java Hidenc --key=$(<task4.key) --ctr=$(<task4.ctr) --offset=$(<task4.offset) --input=task4.data --output=file4.data --size=2048
```

# Simplifications and Assumptions

* The smallest data unit is an AES block.
* No need to worry about padding.
* CTR counters increase by 1 per block, starting at the given initial counter.

# Environment

* Use Java.
* Must run on the course virtual machine.
* Must be executable from a Linux shell.

Helpful tools:  
`ghex`, `bless`, `xxd`, `hexdump`, `dd`

Example dd usage:

```
$ dd if=infile of=outfile bs=1 count=82 seek=784
```

# Hints and Tips

## Scanning the Container

**ECB**:  
* Position-independent  
* Can decrypt full file, search afterward

**CTR**:  
* Position-dependent  
* Must try decryption at every offset

# Java Security Framework

AES is available via JCA/JCE. Look up online resources for help.

# Files

You are provided with:

* `task1.data`, `task1.key`
* `task2.data`, `task2.key`, `task2.offset`
* `task3.data`, `task3.key`, `task3.ctr`
* `task4.data`, `task4.key`, `task4.ctr`, `task4.offset`
* `README.md`

# Submission

Submit the following:

* `file1.data`
* `file2.data`
* `file3.data`
* `file4.data`
* `Hiddec.java`
* `Hidenc.java`

If you do all tasks, your programs must support both ECB and CTR.
