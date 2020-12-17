# Authentication & Authorization Using Jwt In Spring Boot

# I. Khởi Tạo Project Với Intellij

Các Dependencies cần sử dụng bao gồm:

- spring-boot-starter-data-jpa
- spring-boot-starter-security
- spring-boot-starter-web
- jjwt
- mysql-connector-java

File Pom của project như sau:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.4.0</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>com.minhduc.</groupId>
    <artifactId>jwt</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>jwtguide</name>
    <description>Demo project for Spring Boot</description>

    <properties>
        <java.version>11</java.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-jpa</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <!-- https://mvnrepository.com/artifact/io.jsonwebtoken/jjwt -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.1</version>
        </dependency>

        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <scope>runtime</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>

</project>
```

# II. Các bước tiến hành

## 1. Tiến hành tạo các Entity sử dụng trong project.

- Ở đây, mình tạo 2 entity là User và Role, một User có thể có nhiều role, một role có thể có nhiều user. Đây là quan hệ Many To Many. Ta sử dụng @ManyToMany annotation để biểu diễn cho quan hệ này cho các entity mà ta lưu xuống database. Lưu ý ở @@JoinColumn và @InverseJoinColumn chính là khóa chỉnh của bảng hiện tại (User) và khóa chính của bảng mà ta tham chiếu tới (role_id).
- Để sử dụng Role cho thuận tiện, mình sử dụng kiểu enum. Role có thể nhận các giá trị như ROLE_USER, ROLE_ADMIN, ROLE_MODERATOR
- Để lưu thuộc tính role_name với kiểu dữ liệu là một Enum, ta phải sử dụng @Enumerated(EnumType.STRING)

Code cho các Entity Object được trình bày như sau:

```java
package com.minhduc.jwt.entity;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String username;
    private String password;
    private String email;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    public User() {
    }

    public User(String username, String password, String email) {
        this.username = username;
        this.password = password;
        this.email = email;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}
```

Role.class

```java
package com.minhduc.jwt.entity;

import javax.persistence.*;

@Entity
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Enumerated(EnumType.STRING)
    private RoleEnum name;

    public Role() {
    }

    public Role(RoleEnum name) {
        this.name = name;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public RoleEnum getName() {
        return name;
    }

    public void setName(RoleEnum name) {
        this.name = name;
    }
}
```

RoleEnum

```java
package com.minhduc.jwt.entity;

public enum RoleEnum {
    ROLE_USER,
    ROLE_ADMIN,
    ROLE_MODERATOR
}
```

## 2. Tiến Hành Tạo Repository Cho Các Entity Object Ta Sử Dụng

- Ở đây, ta có 2 object là User và Role, ta tiến hành tạo repository cho chúng nó
- Tận dụng JPA, ta sẽ kế thừa JpaRepository để tận dụng lại

UserRepository.java

```java
package com.minhduc.jwt.repository;

import com.minhduc.jwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    Boolean existsByEmail(String email);
}
```

RoleRepository.java

```java
package com.minhduc.jwt.repository;

import com.minhduc.jwt.entity.Role;
import com.minhduc.jwt.entity.RoleEnum;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(RoleEnum name);
}
```

## 3. Tiến Hành Tạo Package UI (Request, Response Model)

- Ta tiến hành tạo Request, Response Model
- Request sẽ bao gồm: UserLoginRequestModel chứa username, password và UserRegisterRequestModel chứa các thông tin cần thiết để có thể tạo một tài khoản
- Response sẽ bao gồm các thông tin accessToken, Id, Username, Password, ... để trả lại cho người dùng

UserLoginRequestModel.java

```java
package com.minhduc.jwt.ui.request;

public class UserLoginRequestModel {
    private String username;
    private String password;

    public UserLoginRequestModel() {

    }

    public UserLoginRequestModel(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
```

UserRegisterRequestModel.java

```java
package com.minhduc.jwt.ui.request;

import java.util.Set;

public class UserRegisterRequestModel {

    private String username;

    private String email;

    private Set<String> role;

    private String password;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<String> getRole() {
        return this.role;
    }

    public void setRole(Set<String> role) {
        this.role = role;
    }
}
```

Response

```java
package com.minhduc.jwt.ui.response;

import java.util.List;

public class JwtResponse {
    private String token;
    private String type = "Bearer";
    private Long id;
    private String username;
    private String email;
    private List<String> roles;

    public JwtResponse(String accessToken, Long id, String username, String email, List<String> roles) {
        this.token = accessToken;
        this.id = id;
        this.username = username;
        this.email = email;
        this.roles = roles;
    }

    public String getAccessToken() {
        return token;
    }

    public void setAccessToken(String accessToken) {
        this.token = accessToken;
    }

    public String getTokenType() {
        return type;
    }

    public void setTokenType(String tokenType) {
        this.type = tokenType;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public List<String> getRoles() {
        return roles;
    }
}
```

Class hỗ trợ việc truyền Message ra response MessageResponse.java

```java
package com.minhduc.jwt.ui.response;

public class MessageResponse {

    private String message;

    public MessageResponse(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
```

## 4. Tạo Các Object Trong Package Utils (Tiện Ích)

- Trong Package này sẽ có 2 đối tượng.
- Một đối tượng chứa các tiện ích với jwt như generate, retrieve username from jwt, valid jwt
- Lớp còn lại dùng để build một User. Lớp này implements UserDetails, đây chính là cái chúng ta trả về từ hàm loadUserByUsername trong UserDetailsServiceIMpl. Lớp này bao gồm các thông tin chính của user như username, password, quyền hạn

JwtUtils.java

```java
package com.minhduc.jwt.utils;

import io.jsonwebtoken.*;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Date;

@Component
public class JwtUtils {

    private static final String jwtSecret = "SECRET";
    private static final Long jwtExpiration = 86400L;

    public String generateJwtToken(Authentication authentication) {
        UserDetailsBuilder userPrincipal = (UserDetailsBuilder) authentication.getPrincipal();

        return Jwts
                .builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + jwtExpiration))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUsernameFromJwt(String token) {
        return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
        } catch (MalformedJwtException e) {
            System.out.println("Invalid JWT signature: {}");
        } catch (ExpiredJwtException e) {
            System.out.println("Invalid JWT signature: {}");
        } catch (UnsupportedJwtException e) {
            System.out.println("Invalid JWT signature: {}");
        } catch (IllegalArgumentException e) {
            System.out.println("Invalid JWT signature: {}");
        }

        return false;
    }
}
```

UserDetailsBuilder.java

```java
package com.minhduc.jwt.utils;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.minhduc.jwt.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

public class UserDetailsBuilder implements UserDetails {

    private Long id;
    private String username;

    @JsonIgnore
    private String password;
    private String email;

    private Collection<? extends GrantedAuthority> authorities;

    public UserDetailsBuilder(Long id, String username, String password, String email, Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.username = username;
        this.password = password;
        this.email = email;
        this.authorities = authorities;
    }

    public static UserDetailsBuilder build(User user) {
        List<GrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        return new UserDetailsBuilder(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getPassword(),
                authorities);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
```

## 5. Tạo UserDetailsServiceImpl

- Khi sử dụng Spring Security, ta cần phải xây dựng một UserDetailsService
- Service này sẽ giúp chúng ta load user từ phía dưới database lên và xây dựng lên một Authentication Object

UserDetailsServiceImpl.java

```java
package com.minhduc.jwt.service;

import com.minhduc.jwt.entity.User;
import com.minhduc.jwt.repository.UserRepository;
import com.minhduc.jwt.utils.UserDetailsBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserDetailsServiceImpl implements UserDetailsService {

    private UserRepository userRepository;

    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                                    .orElseThrow(() -> new UsernameNotFoundException("Username not found"));

        return UserDetailsBuilder.build(user);
    }
}

```

## 6. Tạo Package Security Và Xây Dựng Các Class Cần Thiết

- Tạo class WebSecurityConfig dùng để config lại Spring Security
- Spring Security sẽ cần biết ta sử dụng loại encode gì để mã hóa mật khẩu. Vì vậy ta phải có một @Bean với loại mã hóa ta cần dùng. Ở đây mình sử dụng Bcrypt

```java
@Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
```

- Để cấu hình lại Spring Security, ta cần phải thêm các annotation như sau @EnableWebSecurity. Class này phải extends WebSecurityConfigurerAdapter.
- Ta phải overdrive lại 2 method bao gồm
    - Để báo cho Spring Security biết ta sử dụng userDetailsService của chúng ta và sử dụng Bcrypt là phương thức mã hóa

    ```java
    @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(userDetailsServiceImpl).passwordEncoder(bCryptPasswordEncoder);
        }
    ```

    - Để config lại các resources

    ```java
    package com.minhduc.jwt.config;

    import com.minhduc.jwt.filter.AuthenticationFilter;
    import com.minhduc.jwt.filter.JwtAuthFilter;
    import com.minhduc.jwt.service.UserService;
    import org.springframework.context.annotation.Bean;
    import org.springframework.http.HttpMethod;
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
    import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
    import org.springframework.security.config.annotation.web.builders.HttpSecurity;
    import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
    import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
    import org.springframework.security.config.http.SessionCreationPolicy;
    import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
    import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

    @EnableWebSecurity
    @EnableGlobalMethodSecurity(
            prePostEnabled = true,
            securedEnabled = true,
            jsr250Enabled = true)
    public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

        private BCryptPasswordEncoder bCryptPasswordEncoder;
        private UserService userService;

        public WebSecurityConfig(BCryptPasswordEncoder bCryptPasswordEncoder, UserService userService) {
            this.bCryptPasswordEncoder = bCryptPasswordEncoder;
            this.userService = userService;
        }

        @Bean
        @Override
        public AuthenticationManager authenticationManagerBean() throws Exception {
            return super.authenticationManagerBean();
        }

        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder);
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .csrf().disable().cors().disable()
                    .authorizeRequests().antMatchers(HttpMethod.POST, "/register").permitAll()
                    .antMatchers(HttpMethod.GET, "/").permitAll()
                    .antMatchers(HttpMethod.POST, "/signin").permitAll()
                    .anyRequest().authenticated()
                    .and()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            http
                    .addFilter(new JwtAuthFilter(authenticationManager(), userService))
                    .addFilter(getAuthenticationFilter());
        }

        protected AuthenticationFilter getAuthenticationFilter() throws Exception {
            final AuthenticationFilter filter = new AuthenticationFilter(authenticationManager());
            filter.setFilterProcessesUrl("/api/auth");
            return filter;
        }
    }
    ```

    ## 7. Tận Dụng Spring Security Để Login

    - Ta tận dụng lại UsernamePasswordAuthenticationFilter.class của Spring Security để thực hiện Login mà không cần xây dưng lại hàm login trong controller

    AuthenticationFilter.class

    ```java
    package com.minhduc.jwt.filter;

    import com.fasterxml.jackson.databind.ObjectMapper;
    import com.minhduc.jwt.constant.SecurityConstants;
    import com.minhduc.jwt.ui.model.request.UserLoginRequestModel;
    import io.jsonwebtoken.Jwts;
    import io.jsonwebtoken.SignatureAlgorithm;
    import org.springframework.security.authentication.AuthenticationManager;
    import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
    import org.springframework.security.core.Authentication;
    import org.springframework.security.core.AuthenticationException;
    import org.springframework.security.core.userdetails.UserDetails;
    import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

    import javax.servlet.FilterChain;
    import javax.servlet.ServletException;
    import javax.servlet.http.HttpServletRequest;
    import javax.servlet.http.HttpServletResponse;
    import java.io.IOException;
    import java.util.ArrayList;
    import java.util.Date;

    public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

        private final AuthenticationManager authenticationManager;

        public AuthenticationFilter(AuthenticationManager authenticationManager) {
            this.authenticationManager = authenticationManager;
        }

        @Override
        public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
            try {
                UserLoginRequestModel userLoginRequestModel = new ObjectMapper()
                        .readValue(request.getInputStream(), UserLoginRequestModel.class);

                return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(userLoginRequestModel.getEmail(), userLoginRequestModel.getPassword(), new ArrayList<>()));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
            String username = ((UserDetails) authResult.getPrincipal()).getUsername();
            String token = Jwts.builder()
                    .setSubject(username)
                    .setExpiration(new Date(System.currentTimeMillis() + SecurityConstants.EXPIRATION_TIME))
                    .signWith(SignatureAlgorithm.HS512, SecurityConstants.getTokenSecret())
                    .compact();
            response.addHeader(SecurityConstants.HEADER_STRING, "Bearer " + token);
        }
    }
    ```
