# Encryption starter

This is a small project for a module in my master's degree.
The core task is to provide a way to enter spring boots in an encrypted way.
These encrypted properties should be decrypted before being passed to relevant modules.
E.g. the password for a database user should not be written in plaintext in the properties file.
This project should provide a way to write the encrypted variant, hibernate should still receive the decrypted property
so it can work as usual.

## Documentation

For this to work the Spring project provides an interface called `EnvironmentPostProcessor`.
If an implementation of this interface is linked in a specific file called `META-INF/spring.factories` the
implementation will be used for property processing.
Thus, this is a good starting point.

JaSypt ultimately was using a similar approach.
The key difference is that JaSypt uses a custom type of `PropertySource`.
This means that you have to register the property source yourself.
This gives the implementer more flexibility, although you also have to correctly configure it.

Other documentation can be found in the [documentation folder](documentation).
This includes

* instructions on how to [build and configure](documentation/getting_started.md) the processor for spring
* a listing of the [properties the processor listens to](documentation/configuration.md)
* instructions on [how to run the demo app](documentation/running_demo_app.md)

## Folder structure

* [documentation](documentation) as mentioned contains other markdown files documenting the usage of the process etc.
* [demo-app](demo-app) is an example spring boot application using the processor. The application is extremely simple
  and only connects to a database. See the [instructions](documentation/running_demo_app.md) for running the demo app
* [processor](processor) contains the maven project for the processor itself

## Limitations

* For asymmetric or elliptic curve algorithms the provided key is expected to be in ANS.1/PKCS8 format
* For asymmetric or elliptic curve algorithms the key is always treated as the private key

## Todo Steps

- [x] Basic implementation of `EnvironmentPostProcessor` that is "working", i.e. Spring actually calls it. The
  implementation does not really have to do anything.
- [x] Make the implementation do its actual job, i.e. decrypting properties. Limit this feature to just a single
  property `spring.datasource.password`. Also limit the available encryption algorithm to DES and hardcode the key.
- [x] Allow loading keys from different locations
- [x] As the bytes are ultimately interpreted as string data make sure that correct char set is chosen or it is
  customizable
- [x] Check how property placeholders are affected. I.e. `property=something${other.property}`. The best use case is for
  the implemented processor to apply before placeholders are reworked. It is more likely that a user has credentials
  used in multiple places than that he is creating a single hexString via multiple other properties
- [x] Make the implementation more customizable, i.e. support different algorithms
- [x] Handle the case where the algorithm for generating the key is different from the encryption algorithm. This is
  e.g. the case for AES/CBC/PKCS5Padding which is valid for `Cipher` but not for `KeyFactory`
- [x] Figure out an easy way to tell the processor which properties should actually be processed.
- [x] Test if elliptic curve cryptography, other asymmetric algorithms (ElGamal) and multi key algorithms can be
  supported
- [ ] Increase test cases
- [ ] Improve documentation
- [x] Make the project work as a separate dependency
