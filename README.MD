


```scala
import iaksmlka._
import io.circe.syntax._

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
// Jws(List(Alg(HS512), Typ(JWT)),List(Iss(iss), Sub(sub), Exp(42), Custom(foo,"bar")),pJmlaKB0CrfzhI7Neo4KwsPZW3w6wsaoARMockF9D0kVrcdhUjDww+REEh8WOCjYBE+ZChPDl10R7M4ybxmmIw==)

println(jwt.asJson.noSpaces)
// {"header":{"alg":"HS512","typ":"JWT"},"payload":{"iss":"iss","sub":"sub","exp":42,"foo":"bar"},"signature":"pJmlaKB0CrfzhI7Neo4KwsPZW3w6wsaoARMockF9D0kVrcdhUjDww+REEh8WOCjYBE+ZChPDl10R7M4ybxmmIw=="}

println(jwt.compact)
// eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJpc3MiLCJzdWIiOiJzdWIiLCJleHAiOjQyLCJmb28iOiJiYXIifQ==.pJmlaKB0CrfzhI7Neo4KwsPZW3w6wsaoARMockF9D0kVrcdhUjDww+REEh8WOCjYBE+ZChPDl10R7M4ybxmmIw==
```

