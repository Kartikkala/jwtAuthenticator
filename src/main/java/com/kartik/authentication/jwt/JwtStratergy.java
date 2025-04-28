package com.kartik.authentication.jwt;

import com.fasterxml.jackson.databind.JsonNode;
import com.kartik.authentication.exceptions.TokenNotFound;
import com.kartik.authentication.jwt.config.JwtLoginConfig;
import com.kartik.authentication.interfaces.AuthenticationStratergy;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.util.HashMap;



@Component
public class JwtStratergy implements AuthenticationStratergy {

    private final JwtUtil jwtUtil;
    private final JwtLoginConfig config;

    @Autowired
    public JwtStratergy(JwtUtil util,@Lazy JwtLoginConfig config)
    {
        this.jwtUtil = util;
        this.config = config;
    }
    public Boolean authenticate(HttpServletRequest request, HttpServletResponse response)
    {
        String token = request.getHeader("Authorization");
        if(token == null || token.isEmpty())
        {
            throw new TokenNotFound("Cannot find token in Authorization header!");
        }

        HashMap<String, String> user = new HashMap<>();

        try {
            for(String field : config.getClaimFields())
            {
                user.put(field, jwtUtil.extractClaim(token, claims -> claims.get(field, String.class)));
            }
            request.setAttribute("user", user);
        } catch (ExpiredJwtException e) {
            sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Token expired");
            return false;
        } catch (MalformedJwtException e) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "Invalid token format");
            return false;
        } catch (SignatureException e) {
            sendErrorResponse(response, HttpServletResponse.SC_UNAUTHORIZED, "Invalid token signature");
            return false;
        } catch (UnsupportedJwtException e) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "Unsupported token");
            return false;
        } catch (JwtException e) {
            sendErrorResponse(response, HttpServletResponse.SC_BAD_REQUEST, "Invalid token");
            return false;
        }
        return true;
    }

    private void sendErrorResponse(HttpServletResponse response, int status, String message) {
        try {
            response.sendError(status, message);
        }
        catch (IOException e)
        {
            System.out.println("Exception in sending error response");
            System.out.println(e);
        }
    }


    public Boolean login(HttpServletRequest request, HttpServletResponse response) throws IOException
    {
        Claims claims = Jwts.claims();
        String subject = null;

        HashMap<String, Object> requestBody = (HashMap<String, Object>)request.getAttribute("user");
        if(requestBody == null)
        {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

        for (String field : requestBody.keySet()) {
            Object value = requestBody.get(field);
            if (value != null) {
                claims.put(field, value);
            }
            if (field.equals(config.getSubjectField())) {
                subject = (String)value;
            }
        }

        if (subject == null) {
            throw new RuntimeException("Subject field missing in request");
        }

        String token = jwtUtil.generateToken(subject, claims);

        response.setHeader("Authorization", token);
        return true;
    }

    public Boolean supports(HttpServletRequest request)
    {
        String token = request.getHeader("Authorization");
        return token != null;
    }

    public String getName()
    {
        return "jwt";
    }
}
