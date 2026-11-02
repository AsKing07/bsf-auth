package fr.bsf.auth;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * Configuration minimale du serveur d'autorisation pour le spike BSF-9.
 *
 * <p>Ce que le spike veut prouver (D-019) : un utilisateur se connecte via la redirection,
 * et le jeton reçu se valide avec la clé publique publiée sur l'endpoint JWKS.
 *
 * <p>Écarts volontaires avec la configuration d'exemple de la documentation :
 * <ul>
 *   <li>client public + PKCE obligatoire (c'est ce que fera le front Angular) ;</li>
 *   <li>endpoint JWKS déplacé sur {@code /.well-known/jwks.json}, chemin retenu dans
 *       {@code API_CONTRACTS.md} §7 (le chemin par défaut du framework est {@code /oauth2/jwks}) ;</li>
 *   <li>aucun mot de passe en dur : il est injecté à l'exécution ;</li>
 *   <li>claim {@code roles} ajouté au jeton d'accès (D-014 : comptes et rôles partagés).</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    public static final String CLIENT_ID = "portail-spike";
    public static final String REDIRECT_URI = "http://127.0.0.1:4200/callback";
    /** Second produit fictif, pour prouver le SSO : il réutilise la session ouverte par le premier. */
    public static final String SECOND_CLIENT_ID = "referentiel-spike";
    public static final String SECOND_REDIRECT_URI = "http://127.0.0.1:4300/callback";
    public static final String JWKS_PATH = "/.well-known/jwks.json";
    public static final String SPIKE_USERNAME = "alice.test";

    /** Chaîne dédiée aux endpoints du protocole (authorize, token, jwks, discovery). */
    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .oauth2AuthorizationServer((authorizationServer) -> {
                http.securityMatcher(authorizationServer.getEndpointsMatcher());
                authorizationServer.oidc(Customizer.withDefaults());
            })
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
            // Une requête HTML non authentifiée sur /oauth2/authorize part vers la page de connexion.
            .exceptionHandling((exceptions) -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint("/login"),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));
        return http.build();
    }

    /** Chaîne par défaut : la page de connexion (formulaire) pour tout le reste. */
    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated())
            .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /** Utilisateur fictif unique. Le mot de passe vient de la configuration, jamais du code. */
    @Bean
    UserDetailsService userDetailsService(
            @Value("${bsf.spike.user.password}") String password, PasswordEncoder encoder) {
        return new InMemoryUserDetailsManager(
            User.withUsername(SPIKE_USERNAME).password(encoder.encode(password)).roles("PORTEUR").build());
    }

    /**
     * Deux produits déclarés : le Portail et un second produit fictif (le Référentiel),
     * tous deux clients publics (SPA) : pas de secret, PKCE obligatoire.
     */
    @Bean
    RegisteredClientRepository registeredClientRepository() {
        return new InMemoryRegisteredClientRepository(
            publicClient(CLIENT_ID, REDIRECT_URI),
            publicClient(SECOND_CLIENT_ID, SECOND_REDIRECT_URI));
    }

    private static RegisteredClient publicClient(String clientId, String redirectUri) {
        return RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri(redirectUri)
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .clientSettings(ClientSettings.builder()
                .requireProofKey(true)
                .requireAuthorizationConsent(false)
                .build())
            .build();
    }

    /** Paire de clés RSA générée au démarrage : rien de secret n'est versionné. */
    @Bean
    RSAKey rsaKey() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair keyPair = generator.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyID(UUID.randomUUID().toString())
                .build();
        } catch (Exception ex) {
            throw new IllegalStateException("Génération de la clé RSA impossible", ex);
        }
    }

    @Bean
    JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    /** Décodeur interne au serveur (userinfo, etc.), basé sur la clé publique. */
    @Bean
    JwtDecoder jwtDecoder(RSAKey rsaKey) throws JOSEException {
        return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().jwkSetEndpoint(JWKS_PATH).build();
    }

    /** Ajoute au jeton d'accès la liste des rôles (sans le préfixe ROLE_). */
    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> rolesClaimCustomizer() {
        return (context) -> {
            if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Set<String> roles = context.getPrincipal().getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .filter((authority) -> authority.startsWith("ROLE_"))
                    .map((authority) -> authority.substring("ROLE_".length()))
                    .collect(Collectors.toSet());
                context.getClaims().claim("roles", roles);
            }
        };
    }
}
