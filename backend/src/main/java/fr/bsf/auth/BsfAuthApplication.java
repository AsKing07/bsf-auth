package fr.bsf.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Spike BSF-9 : serveur OIDC minimal (Spring Authorization Server). Pas du code de production. */
@SpringBootApplication
public class BsfAuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(BsfAuthApplication.class, args);
    }
}
