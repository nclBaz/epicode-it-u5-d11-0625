package riccardogulin.u5d11.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import riccardogulin.u5d11.entities.User;

import java.util.Date;

@Component
public class TokenTools {

	private final String secret;

	public TokenTools(@Value("${jwt.secret}") String secret) {
		this.secret = secret;
	}

	// Jwts (proviene da jjwt-api) fornisce principalmente 2 metodi: builder() e parser(), il primo lo usiamo per creare i token,
	// il secondo per leggerli (eventualmente estraendo info dal token) e validarli

	public String generateToken(User user) {
		return Jwts.builder()
				.issuedAt(new Date(System.currentTimeMillis())) // Data di emissione (IaT - Issued At), va messa in millisecondi
				.expiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 7)) // Data di scadenza (Expiration Date), anche questa in millisecondi
				.subject(String.valueOf(user.getUserId())) // Subject ovvero a chi appartiene il token. Inseriamo l'id del proprietario <-- MAI METTERE DATI SENSIBILI AL SUO INTERNO
				.signWith(Keys.hmacShaKeyFor(secret.getBytes())) // Firmiamo il token con un segreto e con un algoritmo apposito
				.compact();
	}

//	public void verifyToken() {
//	}
}
