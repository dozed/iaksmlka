package iaksmlka

import org.scalacheck.Gen
import org.scalacheck.Arbitrary

import io.circe._

object GenInstances {

  val stringOrListGen: Gen[StringOrList] = Gen.oneOf(
    Arbitrary.arbitrary[String] map (x => stringOrList(x)),
    Arbitrary.arbitrary[List[String]] map (x => stringOrList(x))
  )

  val issGen: Gen[Claim.Iss] = Arbitrary.arbitrary[String] map Claim.Iss
  val subGen: Gen[Claim.Sub] = Arbitrary.arbitrary[String] map Claim.Sub
  val audGen: Gen[Claim.Aud] = Gen.oneOf(
    Arbitrary.arbitrary[String] map (x => stringOrList(x)),
    Arbitrary.arbitrary[List[String]] map (x => stringOrList(x))
  ) map Claim.Aud
  val expGen: Gen[Claim.Exp] = Arbitrary.arbitrary[Long] map Claim.Exp
  val nbfGen: Gen[Claim.Nbf] = Arbitrary.arbitrary[Long] map Claim.Nbf
  val iatGen: Gen[Claim.Iat] = Arbitrary.arbitrary[Long] map Claim.Iat
  val jtiGen: Gen[Claim.Jti] = Arbitrary.arbitrary[String] map Claim.Jti
  val customGen: Gen[Claim.Custom] =
    for {
      key <- Arbitrary.arbitrary[String]
      value <- Arbitrary.arbitrary[String] map Json.fromString
    } yield Claim.Custom(key, value)

  val claimGen: Gen[Claim] = Gen.oneOf(issGen, subGen, audGen, expGen, nbfGen, iatGen, jtiGen, customGen)
  val claimsGen: Gen[List[Claim]] = Gen.someOf(issGen, subGen, audGen, expGen, nbfGen, iatGen, jtiGen, customGen) map (_.toList)

  val typGen: Gen[Header.Typ] = Arbitrary.arbitrary[String] map Header.Typ
  val ctyGen: Gen[Header.Cty] = Arbitrary.arbitrary[String] map Header.Cty
  val algorithmGen: Gen[Algorithm] = Gen.oneOf(Algorithm.HS256, Algorithm.HS384, Algorithm.HS512)
  val algGen: Gen[Header.Alg] = Gen.oneOf(Algorithm.HS256, Algorithm.HS384, Algorithm.HS512) map Header.Alg

  val headerGen: Gen[Header] = Gen.oneOf(typGen, ctyGen, algGen)

}
