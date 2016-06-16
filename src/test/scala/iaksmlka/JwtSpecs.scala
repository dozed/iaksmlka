package iaksmlka

import org.specs2.mutable.Specification
import org.specs2.scalaz.ScalazMatchers
import org.specs2.ScalaCheck
import org.scalacheck.Prop.forAll

import scalaz._, Scalaz._
import io.circe.syntax._

import GenInstances._

class JwtSpecs extends Specification with ScalazMatchers with ScalaCheck {

  val secret = "thequickbrownfoxjumpsoverthelazydog"

  "A JWT can be signed" in {

    val jwtE = Jwt.sign(List(Claim.Custom("foo", "".asJson)), secret, Algorithm.HS256)
    jwtE should beRightDisjunction

  }

  "A JWT can be signed and validated" in {

    forAll (claimsGen, algorithmGen) { case (claims, alg) =>

      val jwtE = Jwt.sign(claims, secret, alg)
      jwtE should beRightDisjunction

      val jwt = jwtE getOrElse ???

      val expected = List(
        Header.Alg(alg),
        Header.Typ("JWT")
      )

      jwt.header should beEqualTo(expected)

      Jwt.validate(jwt.compact, secret) should beRightDisjunction(jwt)
      Jwt.validate(jwt.compact, "foo") should beLeftDisjunction

    }

  }


}
