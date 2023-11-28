# Security

Securing a Spring MVC application involves implementing various security measures to protect against common vulnerabilities and attacks. Spring Security is a powerful and widely used framework for securing Spring-based applications.

### 1. **Use Spring Security:**
   - Integrate Spring Security into your Spring MVC application. This framework provides comprehensive security features for authentication, authorization, and protection against common security threats.

### 2. **Authentication:**
   - Configure Spring Security to handle authentication. You can use various authentication providers such as in-memory authentication, JDBC authentication, or custom authentication providers.
   - Enable strong password encoding and consider using techniques like BCrypt.

### 3. **Authorization:**
   - Define and enforce access controls using Spring Security's authorization features. Use annotations like `@Secured` or `@PreAuthorize` on methods to control access at the method level.
   - Implement role-based access control (RBAC) if needed.

### 4. **Securing URLs:**
   - Configure URL-based security rules to control access to different parts of your application. This can be done in the Spring Security configuration.

### 5. **Cross-Site Request Forgery (CSRF) Protection:**
   - Enable CSRF protection in your Spring Security configuration to prevent CSRF attacks. Spring Security provides built-in support for CSRF protection.

### 6. **Cross-Origin Resource Sharing (CORS):**
   - Configure CORS settings to control which domains are allowed to access your APIs.

### 7. **Session Management:**
   - Configure session management settings in Spring Security, such as session timeout, session fixation protection, and secure session cookies.

### 8. **Secure Cookies:**
   - Set secure and HttpOnly flags on cookies to enhance cookie security. This can be configured in your Spring Security settings.

### 9. **Security Headers:**
   - Use security headers like Content Security Policy (CSP), Strict-Transport-Security (HSTS), and X-Content-Type-Options to enhance browser security.

### 10. **Input Validation:**
   - Always validate and sanitize user inputs to prevent common security vulnerabilities such as Cross-Site Scripting (XSS) and SQL injection.

### 11. **Logging and Auditing:**
   - Implement logging and auditing mechanisms to monitor security events and detect suspicious activities. Use Spring AOP (Aspect-Oriented Programming) for cross-cutting concerns like logging.

### 12. **Dependency Scanning:**
   - Regularly scan and update dependencies, including Spring Security, to patch any known security vulnerabilities.

### 13. **Error Handling:**
   - Customize error handling to provide user-friendly error messages while preventing the disclosure of sensitive information.

### 14. **Secure File Uploads:**
   - If your application allows file uploads, implement proper validation and handling to prevent security issues related to file uploads.

### 15. **SSL/TLS:**
   - Always use HTTPS to encrypt data in transit. Configure your server to use strong SSL/TLS protocols and ciphers.

### 16. **Security Testing:**
   - Conduct regular security testing, including penetration testing, to identify and address vulnerabilities.

### 17. **User Education:**
   - Educate users about security best practices, such as using strong passwords and being cautious with personal information.

### 18. **Continuous Monitoring:**
   - Implement continuous monitoring of your application for security events and anomalies.

By implementing these practices, you can significantly enhance the security of your Spring MVC application. 


# SpringMVC Authentication & Authorization

This is an example of a Spring MVC application with Spring Security configured for basic authentication and authorization. 

1. **Add Spring Security Dependency:**

```xml
<!-- pom.xml -->
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

2. **Configure Spring Security:**

Create a `SecurityConfig` class to configure Spring Security.

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService() {
        // Create users with different roles
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("admin")
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService());
    }

    @Configuration
    public static class WebSecurityConfig extends WebSecurityConfigurerAdapter {
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests()
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/user/**").hasRole("USER")
                    .antMatchers("/public/**").permitAll()
                    .anyRequest().authenticated()
                    .and()
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                    .and()
                .logout()
                    .permitAll();
        }
    }
}
```

3. **Controller:**

Create a simple controller to handle requests.

```java
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/admin/dashboard")
    public String adminDashboard() {
        return "admin_dashboard";
    }

    @GetMapping("/user/dashboard")
    public String userDashboard() {
        return "user_dashboard";
    }

    @GetMapping("/public/page")
    public String publicPage() {
        return "public_page";
    }
}
```

4. **Thymeleaf Templates:**

Create Thymeleaf templates for the pages.

- `src/main/resources/templates/home.html`
```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home</title>
</head>
<body>
    <h1>Welcome to the Home Page</h1>
</body>
</html>
```

- `src/main/resources/templates/admin_dashboard.html`
```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard</title>
</head>
<body>
    <h1>Welcome to the Admin Dashboard</h1>
</body>
</html>
```

- `src/main/resources/templates/user_dashboard.html`
```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Dashboard</title>
</head>
<body>
    <h1>Welcome to the User Dashboard</h1>
</body>
</html>
```

- `src/main/resources/templates/public_page.html`
```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Public Page</title>
</head>
<body>
    <h1>This is a Public Page</h1>
</body>
</html>
```

# SpringMVC Dependency Scanning

Performing dependency scanning in a Spring MVC project involves checking your project's dependencies for known vulnerabilities. 

### Using OWASP Dependency-Check:

1. **Add Dependency-Check Plugin:**

   Add the `dependency-check-maven` plugin to your Maven project. Open your `pom.xml` file and include the plugin configuration inside the `<build>` and `<plugins>` sections:

   ```xml
   <build>
       <plugins>
           <!-- ... other plugins ... -->
           <plugin>
               <groupId>org.owasp</groupId>
               <artifactId>dependency-check-maven</artifactId>
               <version>6.4.0</version>
               <executions>
                   <execution>
                       <goals>
                           <goal>check</goal>
                       </goals>
                   </execution>
               </executions>
           </plugin>
       </plugins>
   </build>
   ```

2. **Run Dependency-Check:**

   Open a terminal in the root directory of your project and run the following Maven command:

   ```bash
   mvn dependency-check:check
   ```

   This command will analyze your project's dependencies and generate a report on any known vulnerabilities. The report will be available in the `target/dependency-check-report.html` file.

3. **Review the Report:**

   Open the generated HTML report in a web browser to review the findings. The report will provide information about the dependencies, their versions, and any known vulnerabilities.

### Using OWASP Dependency-Check with Gradle

1. **Add Dependency-Check Plugin:**

   Add the `dependency-check-gradle` plugin to your Gradle project. Open your `build.gradle` file and include the plugin configuration:

   ```groovy
   plugins {
       id 'org.owasp.dependencycheck' version '6.4.0'
   }

   dependencyCheck {
       failBuildOnCVSS 5
   }
   ```

2. **Run Dependency-Check:**

   Open a terminal in the root directory of your project and run the following Gradle command:

   ```bash
   ./gradlew dependencyCheckAnalyze
   ```

   This command will analyze your project's dependencies and generate a report on any known vulnerabilities. The report will be available in the `build/reports/dependency-check-report.html` file.

3. **Review the Report:**

   Open the generated HTML report in a web browser to review the findings. The report will provide information about the dependencies, their versions, and any known vulnerabilities.

### HTTPS with SpringMVC
   
Enabling HTTPS in a Spring MVC application involves configuring your web server to handle secure connections and updating your Spring MVC application to use HTTPS.

### 1. Generate a Keystore:

You need to generate a keystore file that will store your SSL certificate. You can use the Java `keytool` utility for this purpose. Open a terminal and run the following command:

```bash
keytool -genkeypair -alias tomcat -keyalg RSA -keysize 2048 -keystore keystore.jks -validity 3650
```

Follow the prompts to provide the required information.

### 2. Configure Spring Boot to use HTTPS:

If you're using Spring Boot, you can configure HTTPS in the `application.properties` or `application.yml` file:

```properties
server.port=8443
server.ssl.key-store=classpath:keystore.jks
server.ssl.key-store-password=your_keystore_password
server.ssl.key-password=your_key_password
```

Replace `your_keystore_password` and `your_key_password` with the passwords you set during the keystore generation.

### 3. Redirect HTTP to HTTPS (Optional):

To enforce the use of HTTPS, you can configure your Spring MVC application to redirect HTTP requests to HTTPS. You can do this in your `WebMvcConfigurer` or by using a `Filter`.

#### Using `WebMvcConfigurer`:

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Override
    public void addViewControllers(ViewControllerRegistry registry) {
        registry.addViewController("/").setViewName("forward:/home");
        registry.addViewController("/home").setViewName("home");
    }

    @Bean
    public WebMvcConfigurer forwardToIndex() {
        return new WebMvcConfigurer() {
            @Override
            public void addViewControllers(ViewControllerRegistry registry) {
                registry.addViewController("/").setViewName("forward:/home");
            }
        };
    }
}
```

#### Using a `Filter`:

```java
import org.springframework.web.filter.OncePerRequestFilter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebFilter
public class HttpsRedirectFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String requestUrl = request.getRequestURL().toString();

        if (requestUrl.startsWith("http://")) {
            String redirectUrl = requestUrl.replace("http://", "https://");
            response.sendRedirect(redirectUrl);
        } else {
            filterChain.doFilter(request, response);
        }
    }
}
```

### 4. Update Your Controllers and Views:

Update your controllers and views to use the HTTPS URLs. For example, if your login form submits to `/login`, make sure it submits to `https://yourdomain.com/login`.

### 5. Test Your Configuration:

Restart your Spring Boot application, and access it using `https://localhost:8443` (assuming you used port 8443 in your configuration). Ensure that everything works as expected over HTTPS.
