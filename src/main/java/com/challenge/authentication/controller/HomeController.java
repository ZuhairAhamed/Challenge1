package com.challenge.authentication.controller;

import com.challenge.authentication.model.ErrorResponseModel;
import com.challenge.authentication.model.JwtRequest;
import com.challenge.authentication.model.JwtResponse;
import com.challenge.authentication.service.UserService;
import com.challenge.authentication.util.JWTUtility;
import io.jsonwebtoken.impl.DefaultClaims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
public class HomeController {

    @Autowired
    private JWTUtility jwtUtility;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @PostMapping("/token")
    public ResponseEntity<?> authenticate(@RequestBody JwtRequest jwtRequest) {

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            jwtRequest.getUsername(),
                            jwtRequest.getPassword()
                    )
            );
        } catch (BadCredentialsException e) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new ErrorResponseModel(new Date(), "Username and Passwords are incorrect."));
        }

        final UserDetails userDetails = userService.loadUserByUsername(jwtRequest.getUsername());
        final String token = jwtUtility.generateToken(userDetails);

        Map<String, String> jwtToken = new HashMap<>();
        jwtToken.put("accessToken", token);

        return ResponseEntity.status(HttpStatus.OK).body(new JwtResponse(jwtToken));
    }

    @GetMapping("/about")
    public ResponseEntity<?> home() {
        try {
            return ResponseEntity.status(HttpStatus.OK).body("Hello World!");
        } catch (DisabledException e){
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new ErrorResponseModel(new Date(), e.getMessage()));
        } catch (Exception e){
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(new ErrorResponseModel(new Date(), e.getMessage()));
        }
    }

    @GetMapping(value = "/refreshtoken")
    public ResponseEntity<?> refreshtoken(HttpServletRequest request) {
        DefaultClaims claims = (DefaultClaims) request.getAttribute("claims");

        Map<String, Object> expectedMap = new HashMap<>(claims);
        String token = jwtUtility.doGenerateRefreshToken(expectedMap, expectedMap.get("sub").toString());

        Map<String, String> jwtToken = new HashMap<>();
        jwtToken.put("accessToken", token);
        return ResponseEntity.ok(new JwtResponse(jwtToken));
    }

}
