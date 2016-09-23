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

  val jkuGen: Gen[Header.Jku] = Arbitrary.arbitrary[String] map Header.Jku
  val jwkGen: Gen[Header.Jwk] = Arbitrary.arbitrary[String] map Header.Jwk
  val kidGen: Gen[Header.Kid] = Arbitrary.arbitrary[String] map Header.Kid
  val x5uGen: Gen[Header.X5u] = Arbitrary.arbitrary[String] map Header.X5u
  val x5cGen: Gen[Header.X5c] = Arbitrary.arbitrary[String] map Header.X5c
  val x5tGen: Gen[Header.X5t] = Arbitrary.arbitrary[String] map Header.X5t
  val x5tS256Gen: Gen[Header.X5tS256] = Arbitrary.arbitrary[String] map Header.X5tS256
  val customHeaderGen: Gen[Header.Custom] = Arbitrary.arbitrary[(String, String)] map { case (key, value) => Header.Custom(key, Json.fromString(value)) }

  val headersGen: Gen[List[Header]] = Gen.zip(algGen, Gen.someOf(
    typGen,
    ctyGen,
    jkuGen,
    jwkGen,
    kidGen,
    x5uGen,
    x5cGen,
    x5tGen,
    x5tS256Gen,
    customHeaderGen
  )).map {
    case(alg, xs) => alg :: xs.toList
  }

}
