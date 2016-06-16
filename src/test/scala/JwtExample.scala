
import iaksmlka._
import io.circe.syntax._

object JwtExample1 extends App {

  val secret = "thequickbrownfoxjumpsoverthelazydog"

  val claims =
    List[Claim](
      Claim.Iss("iss"),
      Claim.Sub("sub"),
      Claim.Exp(42),
      Claim.Custom("foo", "bar".asJson)
    )

  val jwt = Jwt.sign(claims, secret, Algorithm.HS512) getOrElse ???

  println(jwt)
  println(jwt.asJson.noSpaces)
  println(jwt.compact)

}
