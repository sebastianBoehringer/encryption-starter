# Configuration

All properties share the common prefix `dhbw.cas.decryption.`.
This prefix will **not** be repeated in the following table.
Documentation for the properties can also be found in [
`DecryptionConfiguration`](../processor/src/main/java/de/dhbw/cas/encryption/configuration/DecryptionConfiguration.java).

| Property       | description                                                                                                                                                                | values/ type                                                                                    | required |
|----------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------|----------|
| key            | A path to the file containing the key to use for decryption. The file has to contain a valid hex string. Only the first line of the file is used                           | An absolute path to a file in the file system or a relative path to a file on the classpath     | yes      |
| transformation | The transformation to use. The processor registers the BouncyCastle provider. Others might need to be registered to support all possible transformations                   | A valid transformation for `Cipher.getInstance`                                                 | yes      |
| iv             | The initialization vector to use. Some cryptographic algorithms may need one. In case the transformation is in GCM mode, this is treated as a value for the GCM param, oth | A valid hex string                                                                              | no       |
| type           | The type of the selected algorithm. E.g. RSA is `ASYMMETRIC`, DESede is `SYMMETRIC`, ECIES is `ELLIPTIC_CURVE`, etc.                                                       | One of `SYMMETRIC`, `ASYMMETRIC` and `ELLIPTIC_CURVE` although the property is case insensitive | yes      |
| properties     | The names of the properties to decrypt                                                                                                                                     | Comma separated list of property names. Defaults to empty                                       | no       |
| charset        | The charset to use when converting the                                                                                                                                     | A valid name for `Charset.forName(String)`. Defaults to US_ASCII                                | no       |
| enabled        | Flag to easily enable/ disable the processor. Useful for testing or local development where you don't have to encrypt your secrets                                         | Boolean. Defaults to true                                                                       | no       |
