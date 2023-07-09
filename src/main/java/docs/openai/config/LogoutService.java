package docs.openai.config;

import docs.openai.exception.InvalidTokenException;
import docs.openai.exception.TokenNotFoundException;
import docs.openai.token.Token;
import docs.openai.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        final String authorization = request.getHeader("Authorization");

        if (authorization == null) {
            throw new InvalidTokenException("Token is missing");
        } else if (!authorization.startsWith("Bearer ")) {
            throw new InvalidTokenException("Token is invalid");
        }

        final String jwt = authorization.substring(7);

        Token storedToken = tokenRepository.findByToken(jwt)
                .orElseThrow(() -> new TokenNotFoundException("Token not found"));

        if (storedToken != null) {
            storedToken.setIsExpired(true);
            storedToken.setIsRevoked(true);
            tokenRepository.save(storedToken);
            SecurityContextHolder.clearContext();
        }
    }
}
