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
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Component
public class JwtStratergy implements AuthenticationStratergy {

    private JwtUtil jwtUtil;
    private JwtLoginConfig config;

    @Autowired
    public JwtStratergy(JwtUtil util,@Lazy JwtLoginConfig config)
    {
        this.jwtUtil = util;
        this.config = config;
    }
    public Boolean authenticate(HttpServletRequest request, HttpServletResponse response)
    {
        String token = request.getHeader("Authorization");
        System.out.println(token);
        int errorCode = HttpServletResponse.SC_OK;
        if(token == null || token.isEmpty())
        {
            throw new TokenNotFound("Cannot find token in Authorization header!");
        }

        HashMap<String, String> user = new HashMap<>();

        try {
            String email = jwtUtil.extractClaim(token, Claims::getSubject);
            user.put("email", email);
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


    public Map<String, Object> extractRequestFields(HttpServletRequest request, List<String> fields) throws IOException {
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode rootNode = objectMapper.readTree(request.getInputStream());

        Map<String, Object> result = new HashMap<>();

        for (String field : fields) {
            if (rootNode.has(field)) {
                JsonNode node = rootNode.get(field);
                if (node.isTextual()) {
                    result.put(field, node.asText());
                } else if (node.isInt()) {
                    result.put(field, node.asInt());
                } else if (node.isLong()) {
                    result.put(field, node.asLong());
                } else if (node.isDouble()) {
                    result.put(field, node.asDouble());
                } else if (node.isBoolean()) {
                    result.put(field, node.asBoolean());
                } else if (node.isArray() || node.isObject()) {
                    result.put(field, objectMapper.convertValue(node, Object.class));
                } else if (node.isNull()) {
                    result.put(field, null);
                }
            }
        }
        return result;
    }

    public Boolean login(HttpServletRequest request, HttpServletResponse response) throws IOException
    {
        Claims claims = Jwts.claims();
        String subject = null;

        Map<String, Object> requestBody = extractRequestFields(request, config.getClaimFields());

        for (String field : requestBody.keySet()) {
            Object value = requestBody.get(field);

            System.out.println(value);
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
