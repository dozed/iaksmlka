package iaksmlka

import java.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import shapeless.syntax.std.traversable._
import shapeless.syntax.std.tuple._
import shapeless.{:+:, Coproduct, _}

import scala.util.Try
import scalaz._, Scalaz._

import io.circe._
import io.circe.syntax._
import io.circe.parser.parse
import cats.data.Xor


// JSON Web Signature (JWS)
// https://tools.ietf.org/html/rfc7515

trait JwsTypes {

   // TODO the payload can contain an arbitrary sequence of octets
  case class Jws[A:Encoder](
    header: List[Header],
    payload: A,
    signature: JwsSignature
  ) {

    lazy val alg: Algorithm = header.collectFirst { case Header.Alg(x) => x }.get

  }

  type JoseHeader = List[Header]
  type JwsCompact = String
  type JwsSignature = String

  // TODO only valid with an alg header

  sealed trait Header

  object Header {

    case class Typ(value: String) extends Header
    case class Cty(value: String) extends Header
    case class Alg(value: Algorithm) extends Header

    case class Jku(value: String) extends Header
    case class Jwk(value: String) extends Header
    case class Kid(value: String) extends Header
    case class X5u(value: String) extends Header
    case class X5c(value: String) extends Header
    case class X5t(value: String) extends Header
    case class X5tS256(value: String) extends Header

    // non-registered header parameter
    case class Custom(name: String, value: Json) extends Header

  }


  sealed trait Algorithm

  object Algorithm {

    case object HS256 extends Algorithm
    case object HS384 extends Algorithm
    case object HS512 extends Algorithm
    case object RS256 extends Algorithm
    case object RS384 extends Algorithm
    case object RS512 extends Algorithm
    case object ES256 extends Algorithm
    case object ES384 extends Algorithm
    case object ES512 extends Algorithm
    case object NONE extends Algorithm

  }


  sealed trait JwsError extends Throwable

  object JwsError {

    case object NoAlgHeader extends JwsError
    case object InvalidJwsCompact extends JwsError
    case object InvalidSignature extends JwsError
    case object NoneNotSupported extends JwsError
    case object AlgorithmNotSupported extends JwsError
    case class MacError(msg: String) extends JwsError

    case object CustomClaimNotFound extends JwsError
    case object MalformedCustomClaim extends JwsError

  }

}

trait JwsOperations {

  implicit class JwsExt[A:Encoder](jws: Jws[A]) {

    def compact: JwsCompact = {
      val headerAndPayload = Jws.encodeHeaderAndPayload(jws.header, jws.payload)
      s"$headerAndPayload.${jws.signature}"
    }

  }

  implicit class JwsCompanionExt(companion: Jws.type) {

    def sign[A:Encoder](headers: List[Header], payload: A, secret: String, alg: Algorithm): JwsError \/ Jws[A] = {
      for {
        _   <- {
          headers.find({
            case Header.Alg(x) if x == alg => true
            case _ => false
          }) \/> JwsError.NoAlgHeader
        }
        headerAndPayload = Jws.encodeHeaderAndPayload(headers, payload)
        mac <- Jws.computeMac(headerAndPayload, alg, secret)
      } yield {
        Jws[A](headers, payload, mac)
      }
    }

    def validate[A:Decoder:Encoder](compact: JwsCompact, secret: String): JwsError \/ Jws[A] = {
      for {
        jws1 <- decode[A](compact)
        jws2 <- sign[A](jws1.header, jws1.payload, secret, jws1.alg)
        _ <- {
          if (jws1.signature === jws2.signature) ().right
          else JwsError.InvalidSignature.left
        }
      } yield jws1
    }

    def decode[A:Decoder:Encoder](jws: JwsCompact): JwsError \/ Jws[A] = {
      val xs = jws.split('.').toList
      for {
        ys <- xs.toHList[String :: String :: String :: HNil].map(_.tupled) \/> JwsError.InvalidJwsCompact
        (headerText, payloadText, signature) = ys
        header <- decodeFromBase64[List[Header]](headerText) \/> JwsError.InvalidJwsCompact
        claim <- decodeFromBase64[A](payloadText) \/> JwsError.InvalidJwsCompact
        _ <- {
          if (header.collect { case Header.Alg(x) => x }.nonEmpty) ().right
          else JwsError.NoAlgHeader.left
        }
      } yield {
        Jws(header, claim, signature)
      }
    }

    def encodeHeaderAndPayload[A:Encoder](header: List[Header], payload: A): String = {
      val encodedHeader = encodeBase64Url(header.asJson.noSpaces)
      val encodedPayload = encodeBase64Url(payload.asJson.noSpaces)
      val encodedHeaderAndPayload = s"$encodedHeader.$encodedPayload"

      encodedHeaderAndPayload
    }

    def computeMac(encodedHeaderAndPayload: String, algorithm: Algorithm, secret: String): JwsError \/ JwsSignature = {
      def hmac(alg: String): JwsError \/ JwsSignature = Try {
        val mac: Mac = Mac.getInstance(alg)
        mac.init(new SecretKeySpec(secret.getBytes("utf-8"), alg))
        encodeBase64Url(mac.doFinal(encodedHeaderAndPayload.getBytes("utf-8")))
      } cata (_.right, t => JwsError.MacError(t.getMessage).left)

      algorithm match {
        case Algorithm.HS256 => hmac("HmacSHA256")
        case Algorithm.HS384 => hmac("HmacSHA384")
        case Algorithm.HS512 => hmac("HmacSHA512")
        case Algorithm.NONE => JwsError.NoneNotSupported.left
        case _ => JwsError.AlgorithmNotSupported.left
      }
    }

    def decodeFromBase64[A:Decoder](base64: String): Option[A] = {
      for {
        text <- Try(Base64.getDecoder.decode(base64)).toOption
        json <- parse(new String(text)).toOption
        a <- json.as[A].toOption
      } yield a
    }

    def decodeBase64(subject: String): String = new String(Base64.getDecoder.decode(subject))

    def encodeBase64Url(subject: String): String = Base64.getEncoder.encodeToString(subject.getBytes("utf-8"))

    def encodeBase64Url(subject: Array[Byte]): String = Base64.getEncoder.encodeToString(subject)

  }

}

trait JwsInstances {

  implicit def jwsEqual[A:Equal] = Equal.equal[Jws[A]] {
    (a, b) =>
      // TODO order of header fields
      // ISet.fromList(a.header) === ISet.fromList(b.header) &&
      a.header === b.header &&
        a.signature === b.signature &&
        a.payload === b.payload
  }

  implicit def jwsShow[A] = Show.showFromToString[Jws[A]]

  implicit val jwsErrorShow: Show[JwsError] = Show.showA[JwsError]

  implicit val headerEqual = Equal.equalA[Header]
  implicit val headerShow = Show.showA[Header]

  implicit val algorithmDecoder: Decoder[Algorithm] = Decoder[String].map(_.toUpperCase).emap {
    case "HS256" => Xor.right(Algorithm.HS256)
    case "HS384" => Xor.right(Algorithm.HS384)
    case "HS512" => Xor.right(Algorithm.HS512)
    case "RS256" => Xor.right(Algorithm.RS256)
    case "RS384" => Xor.right(Algorithm.RS384)
    case "RS512" => Xor.right(Algorithm.RS512)
    case "ES256" => Xor.right(Algorithm.ES256)
    case "ES384" => Xor.right(Algorithm.ES384)
    case "ES512" => Xor.right(Algorithm.ES512)
    case "NONE" => Xor.right(Algorithm.NONE)
    case x => Xor.left("Expected algorithm (one of: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512, NONE)")
  }

  implicit val algorithmEncoder: Encoder[Algorithm] = Encoder[String].contramap[Algorithm] {
    case Algorithm.HS256 => "HS256"
    case Algorithm.HS384 => "HS384"
    case Algorithm.HS512 => "HS512"
    case Algorithm.RS256 => "RS256"
    case Algorithm.RS384 => "RS384"
    case Algorithm.RS512 => "RS512"
    case Algorithm.ES256 => "ES256"
    case Algorithm.ES384 => "ES384"
    case Algorithm.ES512 => "ES512"
    case Algorithm.NONE => "NONE"
  }

  implicit val headerListDecoder: Decoder[List[Header]] = Decoder.instance[List[Header]] { c =>
    def headerFieldDecoder: (String, Json) => Decoder.Result[Header] = {
      case ("typ", v) => v.as[String].map(Header.Typ)
      case ("cty", v) => v.as[String].map(Header.Cty)
      case ("alg", v) => v.as[Algorithm].map(Header.Alg)
      case ("jku", v) => v.as[String].map(Header.Jku)
      case ("jwk", v) => v.as[String].map(Header.Jwk)
      case ("kid", v) => v.as[String].map(Header.Kid)
      case ("x5u", v) => v.as[String].map(Header.X5u)
      case ("x5c", v) => v.as[String].map(Header.X5c)
      case ("x5t", v) => v.as[String].map(Header.X5t)
      case ("x5t#S256", v) => v.as[String].map(Header.X5tS256)
      case (key, value) => cats.data.Xor.Right(Header.Custom(key, value))
    }

    c.focus.asObject.cata(
      _.toList.map(x => headerFieldDecoder.tupled(x).toOption).sequence[Option, Header].cata(
        xs => Xor.right(xs),
        Xor.left(DecodingFailure("Expected headers", c.history))
      ),
      Xor.left(DecodingFailure("Expected headers", c.history))
    )
  }

  implicit val headersEncoder: Encoder[List[Header]] = Encoder.instance[List[Header]] { xs =>
    val headerFieldEncoder: Header => (String, Json) = {
      case Header.Typ(x) => ("typ", Json.fromString(x))
      case Header.Cty(x) => ("cty", Json.fromString(x))
      case Header.Alg(x) => ("alg", x.asJson)
      case Header.Jku(x) => ("jku", Json.fromString(x))
      case Header.Jwk(x) => ("jwk", Json.fromString(x))
      case Header.Kid(x) => ("kid", Json.fromString(x))
      case Header.X5u(x) => ("x5u", Json.fromString(x))
      case Header.X5c(x) => ("x5c", Json.fromString(x))
      case Header.X5t(x) => ("x5t", Json.fromString(x))
      case Header.X5tS256(x) => ("x5t#S256", Json.fromString(x))
      case Header.Custom(key, value) => (key, value)
    }

    Json.obj(xs map headerFieldEncoder:_*)
  }


  implicit def jwsEncoder[A: Encoder]: Encoder[Jws[A]] =
    Encoder.forProduct3[List[Header], A, JwsSignature, Jws[A]]("header", "payload", "signature")(jws => (jws.header, jws.payload, jws.signature))

  implicit def jwsDecoder[A:Decoder:Encoder]: Decoder[Jws[A]] =
    Decoder.forProduct3[List[Header], A, JwsSignature, Jws[A]]("header", "payload", "signature")((hs, a, sig) => Jws[A](hs, a, sig))


}
