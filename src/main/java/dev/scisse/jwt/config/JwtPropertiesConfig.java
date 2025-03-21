package dev.scisse.jwt.config;

import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@ConfigurationPropertiesScan("dev.scisse.jwt")
public class JwtPropertiesConfig {
}
