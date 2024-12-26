# Running the demo app

## Prerequisites

The demo app is a simple spring boot application that connects to a mysql database.
Before running it you need to

* build and install the processor with `mvn install` as the processor is not distributed in maven central or other
  repositories
* have a mysql/mariadb installation running on localhost:3306 (that is compatible with version 3.5.1 of the mariadb java
  driver)
* the mysql/mariadb server has to have a database called `test`
* the mysql/mariadb has to have a user called `root` with password `root` that has access to the `test` database

## Running the app

Actually running the app is as simple as using the context options of your IDE or executing `mvn spring-boot:run` in the
directory [demo-app](../demo-app).
When the application is run it should start, successfully set up the hikari connection pool for the database and then
immediately exit.
