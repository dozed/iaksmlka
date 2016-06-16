package iaksmlka

import org.specs2.mutable.Specification
import org.specs2.scalaz.ScalazMatchers

import scalaz._
import Scalaz._

class JwsSpecs extends Specification with ScalazMatchers {

  "A JWS can be signed and validated" in {

    val hs = List(
      Header.Typ("foo"),
      Header.Cty("bar"),
      Header.Alg(Algorithm.HS256)
    )

    val jws = Jws.sign[String](hs, "foo", "secret", Algorithm.HS512) getOrElse ???

    jws.compact should_== "eyJhbGciOiJIUzUxMiIsInR5cCI6ImZvbyIsImN0eSI6ImJhciJ9.ImZvbyI=.Y4391GGuF7CrGZARVlLJKw57KD48elIE0FA7dpVil+15PngxTSXOJ7ZdZ+Op9fdYl647Hxcb+wTs8TIbONzhHg=="

    val expected = List(
      Header.Alg(Algorithm.HS512),
      Header.Typ("foo"),
      Header.Cty("bar")
    )

    jws.header should beEqualTo(expected)

    Jws.validate[String](jws.compact, "secret") should beRightDisjunction
    Jws.validate[String](jws.compact, "notsecret") should beLeftDisjunction

  }

  "An invalid JWS cant be validated" in {

    val jws1 = "eyJhbGciOiJIUzUxMiIsInR5cCI6ImZvbyIsImN0eSI6ImJhciJ9.ImZvbyI=.Y4391GGuF7CrGZARVlLJKw57KD48elIE0FA7dpVil+15PngxTSXOJ7ZdZ+Op9fdYl647Hxcb+wTs8TIbONzhHg=="
    val jws2 = "eyJhbGciOiJIUzUxMiIsInR5cCI6ImZvbyIsImN0eSI6ImJhciJ9.ImZvbyI=.Y4391GGuF7CrGZARVlLJKw57KD48elIE0FA7dpVil+15PngxTSXOJ7ZdZ+Op9fdYl647Hxcb+wTs8TIONzhHg=="
    val jws3 = "eyJhbGciOiJIUzUxMiIsInR5cCI6ImZvbyIsImN0eSI6ImJhciJ9ImZvbyI=.Y4391GGuF7CrGZARVlLJKw57KD48elIE0FA7dpVil+15PngxTSXOJ7ZdZ+Op9fdYl647Hxcb+wTs8TIONzhHg=="

    Jws.validate[String](jws1, "secret") should beRightDisjunction
    Jws.validate[String](jws2, "secret") should_== -\/(JwsError.InvalidSignature)
    Jws.validate[String](jws3, "secret") should_== -\/(JwsError.InvalidJwsCompact)

  }

  "Algorithm.NONE is not supported when signing" in {

    val hs = List(
      Header.Typ("foo"),
      Header.Cty("bar")
    )

    Jws.sign[String](hs, "foo", "secret", Algorithm.NONE) should beLeftDisjunction(JwsError.NoneNotSupported)

  }

}
