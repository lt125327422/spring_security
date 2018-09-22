package com.chino.cocoa.spring_security;


import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;

public class MyPasswordEncoder implements PasswordEncoder {


    /**
     * 加密方法
     *
     * @param charSequence
     * @return
     */
    @Override
    public String encode(CharSequence charSequence) {

        String encodingId = "bcrypt";
        Map<String, PasswordEncoder> encoders = new HashMap<>();
        encoders.put(encodingId, new BCryptPasswordEncoder());
//        encoders.put("ldap", new LdapShaPasswordEncoder());
//        encoders.put("MD4", new Md4PasswordEncoder());
//        encoders.put("MD5", new MessageDigestPasswordEncoder("MD5"));
//        encoders.put("noop", NoOpPasswordEncoder.getInstance());
        encoders.put("pbkdf2", new Pbkdf2PasswordEncoder());
        encoders.put("scrypt", new SCryptPasswordEncoder());
//        encoders.put("SHA-1", new MessageDigestPasswordEncoder("SHA-1"));
//        encoders.put("SHA-256", new MessageDigestPasswordEncoder("SHA-256"));
//        encoders.put("sha256", new StandardPasswordEncoder());
        PasswordEncoder passwordEncoder =   new DelegatingPasswordEncoder(encodingId, encoders);


        /**
         * spring security 5不需要配置密码的加密方式，而是用户密码加前缀的方式表明加密方式，如：
         *
         * {MD5}88e2d8cd1e92fd5544c8621508cd706b代表使用的是MD5加密方式；
         * {bcrypt}$2a$10$eZeGvVV2ZXr/vgiVFzqzS.JLV878ApBgRT9maPK1Wrg0ovsf4YuI6代表使用的是bcrypt加密方式。
         */

        return null;
    }

    /**
     * 匹配方法
     *
     * @param charSequence
     * @param s
     * @return
     */
    @Override
    public boolean matches(CharSequence charSequence, String s) {
        return false;
    }





}
