package com.playground.bootadmin.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import de.codecentric.boot.admin.server.config.AdminServerProperties;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
  private final AdminServerProperties adminServer;

  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    final SavedRequestAwareAuthenticationSuccessHandler loginSuccessHandler = new SavedRequestAwareAuthenticationSuccessHandler();
    loginSuccessHandler.setTargetUrlParameter("redirectTo");
    loginSuccessHandler.setDefaultTargetUrl(this.adminServer.path("/applications"));

    http.csrf(
        csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()).ignoringRequestMatchers(this.adminServer.path("/logout"),
            this.adminServer.path("/instances"), this.adminServer.path("/instances/**"), this.adminServer.path("/actuator/**")))
        .httpBasic(Customizer.withDefaults())
        .formLogin(login -> login.loginPage(this.adminServer.path("/login")).successHandler(loginSuccessHandler)
            .defaultSuccessUrl(this.adminServer.path("/applications")))
        .logout(logout -> logout.logoutUrl(this.adminServer.path("/logout"))).authorizeHttpRequests(authorizeRequests -> authorizeRequests
            .requestMatchers(this.adminServer.path("/login"), this.adminServer.path("/assets/**")).permitAll().anyRequest().authenticated());

    return http.build();
  }

  @Bean
  WebSecurityCustomizer webSecurityCustomizer() {
    return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
  }
}
