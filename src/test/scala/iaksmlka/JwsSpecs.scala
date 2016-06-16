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

    val expected = List(
      Header.Alg(Algorithm.HS512),
      Header.Typ("foo"),
      Header.Cty("bar")
    )

    jws.header should beEqualTo(expected)

    Jws.validate[String](jws.compact, "secret") should beRightDisjunction
    Jws.validate[String](jws.compact, "notsecret") should beLeftDisjunction

  }

}
