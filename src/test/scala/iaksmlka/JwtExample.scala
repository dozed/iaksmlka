package iaksmlka

import shapeless._
import io.circe._
import io.circe.syntax._
import io.circe.parser.parse

object JwtExample extends App {

  // example

  val jws1 = Jws[List[Claim]](
    List(
      Header.Typ("foo"),
      Header.Cty("bar"),
      Header.Alg(Algorithm.HS384)
    ),
    List(
      Claim.Iss("iss"),
      Claim.Sub("sub"),
      Claim.Aud(Coproduct[StringOrList]("aud")),
      Claim.Aud(Coproduct[StringOrList](List("aud", "aud2"))),
      Claim.Exp(42),
      Claim.Nbf(42),
      Claim.Iat(42),
      Claim.Jti("jti"),
      Claim.Custom("foo", "\"bar\"")
    ),
    "foo"
  )


  val json = jws1.asJson
  val sig2 = json.as[Jws[List[Claim]]] getOrElse ???

  println(json.noSpaces)
  // TODO order of headers/claims
  println(jws1 == sig2)
  println(jws1)
  println(sig2)

  val secret = "thequickbrownfoxjumpsoverthelazydog"

  println(Jwt.sign(jws1.payload, secret, Algorithm.HS512))

  val s1 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJpc3MiLCJzdWIiOiJzdWIiLCJhdWQiOiJhdWQiLCJhdWQiOlsiYXVkIiwiYXVkMiJdLCJleHAiOjQyLCJuYmYiOjQyLCJpYXQiOjQyLCJqdGkiOiJqdGkiLCJmb28iOiJiYXIifQ==.9SCDyruJ9p0SGkzGdMdBc6O5wLK1G7MKtGuNABVEUBnyMDI1HNPo3BRAQhxgylA+cmdjEyeq6FTKY62r0sBemw=="
  val s2 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9.eyJpc3MiOiJpc3MiLCJzdWIiOiJzdWIiLCJhdWQiOiJhdWQiLCJhdWQiOlsiYXVkIiwiYXVkMiJdLCJleHAiOjQyLCJuYmYiOjQyLCJpYXQiOjQyLCJqdGkiOiJqdGkiLCJmb28iOiJiYXIifQ==.9SCDyruJ9p0SGkzGdMdBc6O5wLK1G7MKtGuNABVEUBnyMDI1HNPo3BRAQhxgylA+cmdjEyeq6FTKY62r0sBw=="
  val s3 = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiJ9eyJpc3MiOiJpc3MiLCJzdWIiOiJzdWIiLCJhdWQiOiJhdWQiLCJhdWQiOlsiYXVkIiwiYXVkMiJdLCJleHAiOjQyLCJuYmYiOjQyLCJpYXQiOjQyLCJqdGkiOiJqdGkiLCJmb28iOiJiYXIifQ==.9SCDyruJ9p0SGkzGdMdBc6O5wLK1G7MKtGuNABVEUBnyMDI1HNPo3BRAQhxgylA+cmdjEyeq6FTKY62r0sBw=="


  val r1 = Jwt.validate(s1, secret)
  val r2 = Jwt.validate(s2, secret)
  val r3 = Jwt.validate(s3, secret)


  println(r1) // \/-(())
  println(r2) // -\/(InvalidSignature)
  println(r3) // -\/(InvalidJwsCompact)

  val claims =
    List[Claim](
      Claim.Iss("iss"),
      Claim.Sub("sub"),
      Claim.Aud(Coproduct[StringOrList]("aud")),
      Claim.Aud(Coproduct[StringOrList](List("aud", "aud2"))),
      Claim.Exp(42),
      Claim.Nbf(42),
      Claim.Iat(42),
      Claim.Jti("jti"),
      Claim.Custom("foo", "[\"aab\", \"aabba\"]")
    )

  println(Jwt.sign(claims, "", Algorithm.HS512))
  println(Jwt.sign(claims, "foo", Algorithm.NONE))
  println(Jwt.sign(claims, "foo", Algorithm.HS512))


}


object JwtExample1 extends App {

  val secret = "thequickbrownfoxjumpsoverthelazydog"

  val claims =
    List[Claim](
      Claim.Iss("iss"),
      Claim.Sub("sub"),
      Claim.Exp(42),
      Claim.Custom("foo", "\"bar\"")
    )

  val jwt = Jwt.sign(claims, secret, Algorithm.HS512) getOrElse ???

  println(jwt)
  println(jwt.asJson.noSpaces)
  println(jwt.compact)

}
