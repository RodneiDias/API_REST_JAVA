package med.voll.api.infra.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration // Indica que esta é uma classe de configuração
@EnableWebSecurity // Habilita a segurança da web no projeto
public class SecurityConfigurations {

    @Autowired // Injeta automaticamente o filtro de segurança customizado
    private SecurityFilter securityFilter;

    @Bean // Define um bean gerenciado pelo Spring
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable()) // Desabilita a proteção CSRF (Cross-Site Request Forgery)
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Configura a política de criação de sessão para STATELESS (sem estado)
                .authorizeHttpRequests(req -> {
                    req.requestMatchers("/login").permitAll(); // Permite todas as requisições para o endpoint "/login" sem autenticação
                    req.anyRequest().authenticated(); // Requer autenticação para qualquer outra requisição
                })
                .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class) // Adiciona o filtro customizado antes do filtro de autenticação do Spring
                .build(); // Constrói e retorna a cadeia de filtros de segurança
    }

    @Bean // Define um bean gerenciado pelo Spring
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager(); // Retorna o gerenciador de autenticação padrão do Spring Security
    }

    @Bean // Define um bean gerenciado pelo Spring
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Retorna um codificador de senhas que usa o algoritmo BCrypt
    }
}

