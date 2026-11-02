package fr.bsf.auth;

import static fr.bsf.auth.SecurityConfig.CLIENT_ID;
import static fr.bsf.auth.SecurityConfig.JWKS_PATH;
import static fr.bsf.auth.SecurityConfig.REDIRECT_URI;
import static fr.bsf.auth.SecurityConfig.SECOND_CLIENT_ID;
import static fr.bsf.auth.SecurityConfig.SECOND_REDIRECT_URI;
import static fr.bsf.auth.SecurityConfig.SPIKE_USERNAME;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.CookieManager;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.nimbusds.jose.jwk.JWKSet;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Spike BSF-9 (SPK-01) — preuve de bout en bout du critère de sortie :
 * « un utilisateur se connecte via le flux de redirection, et le jeton reçu est validé
 * avec la clé publique récupérée sur l'endpoint JWKS ».
 *
 * <p>Le test joue le rôle du navigateur et du Portail : il suit les redirections à la main,
 * se connecte avec le formulaire, échange le code (PKCE) contre un jeton, puis valide ce jeton.
 * Le serveur démarre sur un port aléatoire avec un mot de passe aléatoire : rien de secret n'est versionné.
 */
class OidcFlowSpikeTest {

    private static final String PASSWORD = UUID.randomUUID().toString();
    private static final Pattern CSRF = Pattern.compile("<input[^>]*name=\"_csrf\"[^>]*value=\"([^\"]+)\"");

    private static ConfigurableApplicationContext context;
    private static String base;

    @BeforeAll
    static void startServer() {
        context = new SpringApplication(BsfAuthApplication.class)
            .run("--server.port=0", "--bsf.spike.user.password=" + PASSWORD);
        base = "http://127.0.0.1:" + context.getEnvironment().getProperty("local.server.port");
    }

    @AfterAll
    static void stopServer() {
        if (context != null) {
            context.close();
        }
    }

    // ------------------------------------------------------------------ le critère de sortie

    @Test
    void connexionParRedirectionPuisJetonValideAvecLaClePubliqueJwks() throws Exception {
        Pkce pkce = Pkce.generate();
        String state = UUID.randomUUID().toString();
        HttpClient browser = newBrowser();

        // 1. Le Portail redirige vers /oauth2/authorize ; l'utilisateur se connecte ; retour avec un code.
        String redirect = authorizeAndLogin(browser, authorizeUrl(pkce.challenge(), state));
        assertThat(redirect).startsWith(REDIRECT_URI);
        assertThat(queryParam(redirect, "state")).isEqualTo(state);
        String code = queryParam(redirect, "code");
        assertThat(code).isNotBlank();

        // 2. Échange du code contre les jetons (PKCE, client public, sans secret).
        HttpResponse<String> tokens = exchange(code, pkce.verifier());
        assertThat(tokens.statusCode()).as(tokens.body()).isEqualTo(200);
        String accessToken = jsonString(tokens.body(), "access_token");
        String idToken = jsonString(tokens.body(), "id_token");

        // 3a. Validation par un décodeur qui va chercher la clé sur l'endpoint JWKS.
        NimbusJwtDecoder viaJwks = NimbusJwtDecoder.withJwkSetUri(base + JWKS_PATH).build();
        viaJwks.setJwtValidator(JwtValidators.createDefaultWithIssuer(base));
        Jwt jwt = viaJwks.decode(accessToken);

        assertThat(jwt.getSubject()).isEqualTo(SPIKE_USERNAME);
        assertThat(jwt.getIssuer().toString()).isEqualTo(base);
        assertThat(jwt.getAudience()).contains(CLIENT_ID);
        assertThat(jwt.getExpiresAt()).isAfter(Instant.now());
        assertThat(jwt.getClaimAsStringList("roles")).containsExactly("PORTEUR");
        assertThat(viaJwks.decode(idToken).getAudience()).contains(CLIENT_ID);

        // 3b. Validation « hors ligne » : décodeur construit avec la seule clé publique, sans rappeler le serveur.
        //     C'est ce que feront le Référentiel et le Passeport (D-019, point de panne unique évité).
        JWKSet published = JWKSet.parse(get(newBrowser(), base + JWKS_PATH).body());
        assertThat(published.getKeys()).hasSize(1);
        assertThat(published.getKeys().get(0).isPrivate()).as("la clé privée ne doit jamais être publiée").isFalse();
        RSAPublicKey publicKey = published.getKeys().get(0).toRSAKey().toRSAPublicKey();
        JwtDecoder offline = NimbusJwtDecoder.withPublicKey(publicKey).build();
        assertThat(offline.decode(accessToken).getSubject()).isEqualTo(SPIKE_USERNAME);
    }

    // ------------------------------------------------------------------ le SSO, raison d'être de D-019

    @Test
    void unSecondProduitObtientSonTicketSansRedemanderLeMotDePasse() throws Exception {
        HttpClient browser = newBrowser();

        // 1. Connexion complète sur le Portail : le navigateur repart avec le cookie de session de bsf-auth.
        Pkce portail = Pkce.generate();
        String first = authorizeAndLogin(browser, authorizeUrl(CLIENT_ID, REDIRECT_URI, portail.challenge(), "p"));
        assertThat(first).startsWith(REDIRECT_URI);

        // 2. Le même navigateur va sur le second produit : UNE seule requête, et retour direct avec un code.
        //    Aucun passage par /login : c'est le SSO.
        Pkce referentiel = Pkce.generate();
        String second = location(get(browser,
            authorizeUrl(SECOND_CLIENT_ID, SECOND_REDIRECT_URI, referentiel.challenge(), "r")));
        assertThat(second).as("le second produit ne doit pas redemander le mot de passe")
            .startsWith(SECOND_REDIRECT_URI).doesNotContain("/login");
        assertThat(queryParam(second, "state")).isEqualTo("r");

        // 3. Le second produit échange son code et reçoit un jeton émis pour lui, pour le même utilisateur.
        HttpResponse<String> tokens = exchange(SECOND_CLIENT_ID, SECOND_REDIRECT_URI,
            queryParam(second, "code"), referentiel.verifier());
        assertThat(tokens.statusCode()).as(tokens.body()).isEqualTo(200);
        Jwt jwt = NimbusJwtDecoder.withJwkSetUri(base + JWKS_PATH).build()
            .decode(jsonString(tokens.body(), "access_token"));
        assertThat(jwt.getSubject()).isEqualTo(SPIKE_USERNAME);
        assertThat(jwt.getAudience()).contains(SECOND_CLIENT_ID).doesNotContain(CLIENT_ID);
    }

    @Test
    void sansSessionLeSecondProduitPasseParLaConnexion() throws Exception {
        // Témoin du test précédent : un navigateur neuf, sans cookie, est bien renvoyé vers /login.
        String location = location(get(newBrowser(),
            authorizeUrl(SECOND_CLIENT_ID, SECOND_REDIRECT_URI, Pkce.generate().challenge(), "r")));
        assertThat(resolve(location).getPath()).isEqualTo("/login");
    }

    // ------------------------------------------------------------------ ce qui doit être refusé

    @Test
    void unVerifierPkceIncorrectEstRefuse() throws Exception {
        Pkce pkce = Pkce.generate();
        String redirect = authorizeAndLogin(newBrowser(), authorizeUrl(pkce.challenge(), "s"));
        HttpResponse<String> response = exchange(queryParam(redirect, "code"), Pkce.generate().verifier());
        assertThat(response.statusCode()).isEqualTo(400);
        assertThat(response.body()).contains("invalid_grant");
    }

    @Test
    void unCodeNeServQuUneFois() throws Exception {
        Pkce pkce = Pkce.generate();
        String code = queryParam(authorizeAndLogin(newBrowser(), authorizeUrl(pkce.challenge(), "s")), "code");
        assertThat(exchange(code, pkce.verifier()).statusCode()).isEqualTo(200);
        assertThat(exchange(code, pkce.verifier()).statusCode()).isEqualTo(400);
    }

    @Test
    void sansPkceLaDemandeEstRefusee() throws Exception {
        String redirect = authorizeAndLogin(newBrowser(), authorizeUrl(null, "s"));
        assertThat(redirect).startsWith(REDIRECT_URI).contains("error=invalid_request");
    }

    @Test
    void unJetonFalsifieEstRefuse() throws Exception {
        Pkce pkce = Pkce.generate();
        String code = queryParam(authorizeAndLogin(newBrowser(), authorizeUrl(pkce.challenge(), "s")), "code");
        String accessToken = jsonString(exchange(code, pkce.verifier()).body(), "access_token");

        String[] parts = accessToken.split("\\.");
        int middle = parts[2].length() / 2;
        char original = parts[2].charAt(middle);
        String altered = parts[2].substring(0, middle) + (original == 'A' ? 'B' : 'A') + parts[2].substring(middle + 1);
        String tampered = parts[0] + "." + parts[1] + "." + altered;

        NimbusJwtDecoder viaJwks = NimbusJwtDecoder.withJwkSetUri(base + JWKS_PATH).build();
        assertThatThrownBy(() -> viaJwks.decode(tampered)).isInstanceOf(JwtException.class);
    }

    @Test
    void laDecouverteAnnonceLeBonEndpointJwks() throws Exception {
        String discovery = get(newBrowser(), base + "/.well-known/openid-configuration").body();
        assertThat(discovery).contains("\"jwks_uri\":\"" + base + JWKS_PATH + "\"");
    }

    // ------------------------------------------------------------------ outils : le « navigateur »

    private static HttpClient newBrowser() {
        return HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .cookieHandler(new CookieManager())
            .build();
    }

    private static String authorizeUrl(String challenge, String state) {
        return authorizeUrl(CLIENT_ID, REDIRECT_URI, challenge, state);
    }

    private static String authorizeUrl(String clientId, String redirectUri, String challenge, String state) {
        String url = base + "/oauth2/authorize?response_type=code&client_id=" + clientId
            + "&redirect_uri=" + enc(redirectUri) + "&scope=openid&state=" + state;
        if (challenge != null) {
            url += "&code_challenge=" + challenge + "&code_challenge_method=S256";
        }
        return url;
    }

    /** Suit /oauth2/authorize ; si le serveur renvoie vers /login, se connecte puis reprend. Retourne l'URL de retour. */
    private static String authorizeAndLogin(HttpClient browser, String authorizeUrl) throws Exception {
        String location = location(get(browser, authorizeUrl));
        if (resolve(location).getPath().equals("/login")) {
            String page = get(browser, resolve(location).toString()).body();
            Matcher csrf = CSRF.matcher(page);
            assertThat(csrf.find()).as("jeton CSRF introuvable dans la page de connexion").isTrue();

            HttpResponse<String> submit = post(browser, base + "/login",
                "username=" + enc(SPIKE_USERNAME) + "&password=" + enc(PASSWORD) + "&_csrf=" + enc(csrf.group(1)));
            String afterLogin = location(submit);
            assertThat(afterLogin).as("la connexion a échoué").doesNotContain("error");
            location = location(get(browser, resolve(afterLogin).toString()));
        }
        return location;
    }

    private static HttpResponse<String> exchange(String code, String verifier) throws Exception {
        return exchange(CLIENT_ID, REDIRECT_URI, code, verifier);
    }

    private static HttpResponse<String> exchange(String clientId, String redirectUri, String code, String verifier)
            throws Exception {
        return post(newBrowser(), base + "/oauth2/token",
            "grant_type=authorization_code&code=" + enc(code) + "&redirect_uri=" + enc(redirectUri)
                + "&client_id=" + clientId + "&code_verifier=" + enc(verifier));
    }

    /**
     * En-tête Accept d'une vraie navigation de navigateur. Ne PAS y mettre application/json :
     * Spring Security ne mémorise pas une requête qui accepte du JSON (elle est traitée comme un
     * appel d'API), et après la connexion l'utilisateur est renvoyé vers « / » au lieu de
     * reprendre /oauth2/authorize. C'est ce qu'a révélé le premier passage du spike (02/11).
     */
    private static final String BROWSER_ACCEPT = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

    private static HttpResponse<String> get(HttpClient client, String url) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url)).header("Accept", BROWSER_ACCEPT).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static HttpResponse<String> post(HttpClient client, String url, String formBody) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", BROWSER_ACCEPT)
            .POST(HttpRequest.BodyPublishers.ofString(formBody))
            .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static String location(HttpResponse<?> response) {
        assertThat(response.statusCode()).as("redirection attendue, reçu : " + response.body()).isBetween(300, 399);
        return response.headers().firstValue("Location").orElseThrow();
    }

    private static URI resolve(String location) {
        return URI.create(base).resolve(location);
    }

    private static String queryParam(String url, String name) {
        Matcher matcher = Pattern.compile("[?&]" + name + "=([^&]*)").matcher(url);
        return matcher.find() ? java.net.URLDecoder.decode(matcher.group(1), StandardCharsets.UTF_8) : null;
    }

    private static String jsonString(String json, String field) {
        Matcher matcher = Pattern.compile("\"" + field + "\"\\s*:\\s*\"([^\"]+)\"").matcher(json);
        assertThat(matcher.find()).as("champ " + field + " absent de : " + json).isTrue();
        return matcher.group(1);
    }

    private static String enc(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** Couple PKCE (RFC 7636), méthode S256. */
    private record Pkce(String verifier, String challenge) {
        static Pkce generate() throws Exception {
            byte[] random = new byte[32];
            new SecureRandom().nextBytes(random);
            String verifier = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return new Pkce(verifier, Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
        }
    }
}
