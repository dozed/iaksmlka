package iaksmlka

import org.specs2.mutable.Specification
import org.specs2.scalaz.ScalazMatchers
import io.circe._
import io.circe.parser
import io.circe.syntax._
import org.scalacheck.Prop.forAll
import GenInstances._
import org.specs2.ScalaCheck

import scalaz._
import Scalaz._

class JwsSpecs extends Specification with ScalazMatchers with ScalaCheck {

  "A JWS can be signed and validated" in {

    val hs = List(
      Header.Typ("foo"),
      Header.Cty("bar"),
      Header.Alg(Algorithm.HS512)
    )

    Jws.sign[String](hs, "foo", "secret", Algorithm.HS512) should beRightDisjunction[Jws[String]].like {
      case jws =>

        jws.compact should_== "eyJ0eXAiOiJmb28iLCJjdHkiOiJiYXIiLCJhbGciOiJIUzUxMiJ9.ImZvbyI=.0mbvUXJxhiyKPJpkLAvX4rFAwNt12X4DKGh+MpovjrBbq4hXh4QsndnxuYPncrVW0AgutRbOnt8hewJBm53wSQ=="

        val expected = List(
          Header.Typ("foo"),
          Header.Cty("bar"),
          Header.Alg(Algorithm.HS512)
        )

        jws.header should_== expected

        Jws.validate[String](jws.compact, "secret") should beRightDisjunction
        Jws.validate[String](jws.compact, "notsecret") should beLeftDisjunction

    }

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
      Header.Cty("bar"),
      Header.Alg(Algorithm.NONE)
    )

    Jws.sign[String](hs, "foo", "secret", Algorithm.NONE) should beLeftDisjunction(JwsError.NoneNotSupported)

  }

  "An algorithm needs to specified in headers when signing" in {

    val hs = List(
      Header.Typ("foo"),
      Header.Cty("bar")
    )

    Jws.sign[String](hs, "foo", "secret", Algorithm.NONE) should beLeftDisjunction(JwsError.NoAlgHeader)

  }

  "Headers can be converted to JSON" in {

    forAll (headersGen) { case xs =>

      val xs2 = xs.asJson.as[List[Header]] getOrElse ???
      xs should equal(xs2)

    }

  }

}
