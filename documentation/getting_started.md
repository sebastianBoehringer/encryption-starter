# Getting started

## Building the processor yourself

This project is built with Maven and Java 21.
Locally Eclipse Temurin was used, other SDK-flavours might differ in the default values for cryptographic algorithms.
To build the project navigate into the `processor` directory and run `mvn install`.

## Using the processor in your spring boot application

The demo-app gives an example on how to use the processor in a spring boot application.
The steps are:

1. Declare a dependency on the processor
2. Create a file `META-INF/spring.factories` in your `resources` directory if it does not exist yet
3. Put an entry
   `org.springframework.boot.env.EnvironmentPostProcessor=de.dhbw.cas.encryption.processor.DecryptingPropertiesPostProcessor`
   into the file. This causes spring to load and use an instance of the processor
4. Encrypt your properties and set the value to the hex formated bytes in your application properties
5. Mention the names of the properties to decrypt in `dhbw.cas.decryption.properties`
