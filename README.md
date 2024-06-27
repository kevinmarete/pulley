# Pulley Decryption System

This project provides a system for retrieving, decrypting, and processing encrypted challenges from a remote server. It includes a main class `Pulley` for interacting with the server and various decryption method classes for handling different encryption schemes.

## Features

- **Retrieve Challenges**: Fetches encrypted challenges from a remote server.
- **Decrypt Paths**: Supports multiple decryption methods to decrypt paths.
- **Flexible Decryption Mechanisms**: Includes several decryption strategies like Base64, character swapping, circular rotation, and more.

## Classes and Methods

### Pulley

- **get_challenge(input_param: str)**: Retrieves a challenge from the server.
- **decrypt_path(encrypted_path: str, encryption_method: str, level: str)**: Decrypts an encrypted path using the specified decryption method and level.
- **get_param(input_path: str or bytes)**: Formats the input path into the required parameter format.

### DecryptionMethod (Abstract Base Class)

- **decrypt(encryption_path: str, encryption_method: str)**: Abstract method to be implemented by all decryption method classes.

### Decryption Methods

- **Nothing**: Returns the input path as-is.
- **Base64**: Decodes Base64 encoded strings.
- **SwapEveryPairOfCharacters**: Swaps every pair of characters in the string.
- **CircularLeftRotate**: Performs a circular left rotation on the string.
- **EncodeCustomHexChar**: Decodes strings using a custom hexadecimal character set.
- **ScrambledMsgPack**: Decodes a string scrambled using a message pack.

### DecryptionFactory

- **get_decryption_method(level: str)**: Returns the appropriate decryption method class based on the provided level.

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/kevinmarete/pulley.git
    ```
2. Navigate to the project directory:
    ```bash
    cd pulley
    ```
3. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage
1. Run tests:
    ```bash
    python3 -m unittest
    ```
   
2. Run the main script:
    ```bash
    python3 main.py
    ```