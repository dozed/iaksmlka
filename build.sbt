name := "iaksmlka"

version := "1.0"

scalaVersion := "2.11.8"

libraryDependencies ++= Seq(
  "org.scalaz" %% "scalaz-core" % "7.2.2",
  "com.chuusai" %% "shapeless" % "2.3.1",
  "io.circe" %% "circe-core" % "0.4.1",
  "io.circe" %% "circe-parser" % "0.4.1",
  "org.specs2" %% "specs2-core" % "3.7.2" % "test",
  "org.typelevel" %% "scalaz-specs2" % "0.4.0" % "test"
)

exportJars := true

addCompilerPlugin("org.spire-math" %% "kind-projector" % "0.7.1")
