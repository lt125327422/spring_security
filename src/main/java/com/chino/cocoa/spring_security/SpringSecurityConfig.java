package com.chino.cocoa.spring_security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private MyUserService myUserService;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        super.configure(auth);


        //inMemoryAuthentication 从内存中获取
//        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
//                .withUser("admin")
//                .password(new BCryptPasswordEncoder().encode("123456")).roles("ADMIN");
//
//        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
//                .withUser("chino")
//                .password(new BCryptPasswordEncoder().encode("123456")).roles("ADMIN");
//
//
//        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
//                .withUser("cocoa")
//                .password(new BCryptPasswordEncoder().encode("123456")).roles("USER");


        /**
         * 密方式对用户密码进行处理。以前的".password("123456")" 变成了 ".
         * password(new BCryptPasswordEncoder().encode("123456"))" ，
         * 这相当于对内存中的密码进行Bcrypt编码加密。比对时一致，说明密码正确，允许登陆。
         * 如果你现在用的也是从内存中取密码，那么按照上面这么修改后应该会成功登录没有问题的。
         * 如果你用的是在数据库中存储用户名和密码，那么一般是要在用户注册时就使用BCrypt编
         * 码将用户密码加密处理后存储在数据库中。
         * 并且修改configure()方法，加入".passwordEncoder(new BCryptPasswordEncoder())"，
         * 保证用户登录时使用bcrypt对密码进行处理再与数据库中的密码比对。如下：
         */

        //old
//        auth.inMemoryAuthentication().passwordEncoder(new BCryptPasswordEncoder())
//                .withUser("admin").password("123456").roles("ADMIN");


        //使用自定义
        auth.userDetailsService(myUserService);

        //使用数据库
//        auth.jdbcAuthentication().usersByUsernameQuery("").authoritiesByUsernameQuery("")
//                .passwordEncoder(new MyPasswordEncoder());


    }

    /**
     * 配置哪些请求需要放掉
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        super.configure(http);
        http.authorizeRequests().antMatchers("/").permitAll()
                .anyRequest().authenticated()
                .and()
                .logout().permitAll()
                .and()
                .formLogin();

        http.csrf().disable();

    }


    /**
     * 配置放行的
     *
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
//        super.configure(web);


        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");


    }

}
