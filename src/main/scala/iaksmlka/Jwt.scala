package iaksmlka

import shapeless.{:+:, Coproduct, _}
import shapeless.syntax.std.traversable._
import shapeless.syntax.std.tuple._

import io.circe._
import io.circe.syntax._
import io.circe.parser.parse

import scalaz._, Scalaz._

import cats.data.Xor

// JSON Web Token (JWT)
// https://tools.ietf.org/html/rfc7519

trait JwtTypes {

  type Jwt = Jws[List[Claim]]

  type NumericDate = Long

  sealed trait Claim

  object Claim {

    case class Iss(value: String) extends Claim
    case class Sub(value: String) extends Claim
    case class Aud(value: StringOrList) extends Claim
    case class Exp(value: NumericDate) extends Claim
    case class Nbf(value: Long) extends Claim
    case class Iat(value: Long) extends Claim
    case class Jti(value: String) extends Claim

    // user-defined claims
    case class Custom(name: String, value: Json) extends Claim

  }

  implicit val claimEqual = Equal.equalA[Claim]
  implicit val claimShow = Show.showFromToString[Claim]


  // type StringOrList = Coproduct.`String, List[String]`.T
  type StringOrList = String :+: List[String] :+: CNil

  def stringOrList = Coproduct[StringOrList]

}

trait JwtOperations {

  implicit class JwtExt(jwt: Jwt) {

    def exp: Option[Claim.Exp] = jwt.payload.collectFirst { case x: Claim.Exp => x }

    def custom[A: Decoder](key: String): JwsError \/ A = {
      for {
        json <- jwt.payload.collect { case Claim.Custom(k, value) if key == k => value }.headOption \/> JwsError.CustomClaimNotFound
        a <- json.as[A].toOption \/> JwsError.MalformedCustomClaim
      } yield a
    }

  }

  object Jwt {

    def apply(header: List[Header], claims: List[Claim], signature: JwsSignature): Jwt = Jws[List[Claim]](header, claims, signature)

    def validate(compact: JwsCompact, secret: String): JwsError \/ Jwt = {
      Jws.validate[List[Claim]](compact, secret)
    }


    def sign(payload: List[Claim], secret: String, alg: Algorithm): JwsError \/ Jwt = {
      Jws.sign(List(Header.Typ("JWT"), Header.Alg(alg)), payload, secret, alg)
    }

    def compact(payload: List[Claim], secret: String, alg: Algorithm): JwsError \/ JwsCompact = {
      sign(payload, secret, alg) map (_.compact)
    }

  }

}

trait JwtJSONInstances {

  implicit val cnilEncoder: Encoder[CNil] = Encoder.instance[CNil](_ => Json.Null)

  implicit def cconsEncoder[H, T <: Coproduct](implicit headEncode: Lazy[Encoder[H]], tailEncode: Lazy[Encoder[T]]): Encoder[H :+: T] =
    Encoder.instance[H :+: T] {
      case Inl(l) => headEncode.value(l)
      case Inr(r) => tailEncode.value(r)
    }


  implicit val stringOrListDecoder: Decoder[StringOrList] =
    Decoder[List[String]].map(x => stringOrList(x)) or Decoder[String].map(x => stringOrList(x))

  implicit val audDecoder: Decoder[Claim.Aud] =
    Decoder[List[String]].map(x => Claim.Aud(stringOrList(x)))
      .or(Decoder[String].map(x => Claim.Aud(stringOrList(x))))


  val claimEncoder: Claim => (String, Json) = {
    case Claim.Iss(x) => ("iss", x.asJson)
    case Claim.Sub(x) => ("sub", x.asJson)
    case Claim.Aud(x) => ("aud", x.asJson)
    case Claim.Exp(x) => ("exp", x.asJson)
    case Claim.Nbf(x) => ("nbf", x.asJson)
    case Claim.Iat(x) => ("iat", x.asJson)
    case Claim.Jti(x) => ("jti", x.asJson)
    case Claim.Custom(key, value) => (key, value)
  }

  implicit val claimsDecoder: Decoder[List[Claim]] = Decoder.instance[List[Claim]] { c =>
    val claimDecoder: (String, Json) => Decoder.Result[Claim] = {
      case ("iss", v) => v.as[String].map(Claim.Iss)
      case ("sub", v) => v.as[String].map(Claim.Sub)
      case ("aud", v) => v.as[StringOrList].map(Claim.Aud)
      case ("exp", v) => v.as[Long].map(Claim.Exp)
      case ("nbf", v) => v.as[Long].map(Claim.Nbf)
      case ("iat", v) => v.as[Long].map(Claim.Iat)
      case ("jti", v) => v.as[String].map(Claim.Jti)
      case (key, v) => Xor.right(Claim.Custom(key, v))
    }

    c.focus.asObject.cata(
      _.toList.map(x => claimDecoder.tupled(x).toOption).sequence[Option, Claim].cata(
        xs => Xor.right(xs),
        Xor.left(DecodingFailure("Expected claims", c.history))
      ),
      Xor.left(DecodingFailure("Expected claims", c.history))
    )
  }

  implicit val claimsEncoder: Encoder[List[Claim]] = Encoder.instance[List[Claim]] { xs =>
    Json.obj(xs map claimEncoder:_*)
  }


}

