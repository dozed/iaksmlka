package iaksmlka

import org.specs2.mutable.Specification
import org.specs2.scalaz.ScalazMatchers
import org.specs2.ScalaCheck
import org.scalacheck.Prop.forAll

import scalaz._, Scalaz._
import io.circe._
import io.circe.syntax._

import GenInstances._

class JwtSpecs extends Specification with ScalazMatchers with ScalaCheck {

  val secret = "thequickbrownfoxjumpsoverthelazydog"

  val jwtExpected = Jwt(
    List(Header.Typ("JWT"), Header.Alg(Algorithm.HS256)),
    List(Claim.Custom("foo", "".asJson)),
    "/ewv5f/ztU0z+nVBKzulE7n1KqSpEHhDhtpSAseJuzE="
  )

  val jwsCompactExpected = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiIifQ==./ewv5f/ztU0z+nVBKzulE7n1KqSpEHhDhtpSAseJuzE="

  "A JWT can be signed" in {

    Jwt.sign(List(Claim.Custom("foo", "".asJson)), secret, Algorithm.HS256) should beRightDisjunction[Jwt].like {
      case jwt =>
        jwt should_== jwtExpected
        jwt.compact should_== jwsCompactExpected
    }

  }

  "A JWT is validated" in {

    Jwt.validate(jwsCompactExpected, secret) should beRightDisjunction[Jwt].like {
      case jwt =>
        jwt should_== jwtExpected
        jwt.compact should_== jwsCompactExpected
    }

  }

  "A JWT can be signed and validated" in {

    forAll (claimsGen, algorithmGen) { case (claims, alg) =>

      Jwt.sign(claims, secret, alg) should beRightDisjunction[Jwt].like {
        case jwt =>
          val expected = List(
            Header.Typ("JWT"),
            Header.Alg(alg)
          )

          jwt.header should beEqualTo(expected)

          Jwt.validate(jwt.compact, secret) should beRightDisjunction(jwt)
          Jwt.validate(jwt.compact, "foo") should beLeftDisjunction
      }


    }

  }


}
