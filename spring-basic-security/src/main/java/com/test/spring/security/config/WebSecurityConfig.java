package com.test.spring.security.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/", "/home", "/css/**", "/js/**", "/im/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .loginPage("/login")
                .defaultSuccessUrl("/hello", true)
                //                .successHandler((request, response, auth) -> {
                //                    HttpSession session = request.getSession();
                //                })
                .permitAll()
                .and()
                .logout()
                .permitAll();
//                .and()
//                .csrf()
//                .disable();

    }

    /**
     * BCrypt encoder uses at this point. Since Spring security 5 password
     * encoder is a must and if no specific encoder, default encoder do the
     * encodes password which user enters and compare with given password.
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("user")
                .password("$2a$10$NlwDLyRdoAHq.rv.JoDG3Oqtbbloi8eo0fkDC6VkdDBQ8CmmDo1Ye") //asd
                .roles("USER")
                .and()
                .withUser("admin")
                .password("password2")
                .roles("ADMIN", "USER");
    }
}
