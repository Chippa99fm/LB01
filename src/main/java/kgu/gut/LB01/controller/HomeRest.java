package kgu.gut.LB01.controller;

import kgu.gut.LB01.repository.UserRepository;
import kgu.gut.LB01.security.jwt.Provider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/")
public class HomeRest {

    @Autowired
    AuthenticationManager authenticationManager;

    @Autowired
    UserRepository userRepository;

    @Autowired
    PasswordEncoder encoder;

    @Autowired
    Provider provider;

    @GetMapping("/home")
    public ResponseEntity<?> getHome(@RequestHeader("Authorization") String autorization) {
        String token = getJwt(autorization);
        String username = provider.getUserNameFromAccessJwtToken(token);

        return ResponseEntity.ok().body(String.format(" %s, Hello there", username));
    }

    private String getJwt(String token) {
        if (token != null && token.startsWith("Bearer ")) {
            return token.replace("Bearer ","");
        }
        return null;
    }
}
