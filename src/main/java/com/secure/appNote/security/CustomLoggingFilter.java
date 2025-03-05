//package com.secure.appNote.security;
//
//import jakarta.servlet.FilterChain;
//import jakarta.servlet.ServletException;
//import jakarta.servlet.http.HttpServletRequest;
//import jakarta.servlet.http.HttpServletResponse;
//import org.springframework.stereotype.Component;
//import org.springframework.web.filter.OncePerRequestFilter;
//import java.io.IOException;
//import java.util.List;
//
//@Component
//public class CustomLoggingFilter extends OncePerRequestFilter {
//
//    //private final List<String> blockedIPs = List.of("0:0:0:0:0:0:0:1"); // Add blocked IPs here
//
//
//
//    @Override
//    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//            throws ServletException, IOException {
////        String clientIP = request.getRemoteAddr();
////        System.out.println("Client Ip is : " + clientIP);
////        if (blockedIPs.contains(clientIP)) {
////            response.setStatus(HttpServletResponse.SC_FORBIDDEN); // 403 Forbidden
////            response.getWriter().write("Access Denied");
////            return;
////        }
//        System.out.println("CustomLoggingFilter - Request URI: " + request.getRequestURI());
//        filterChain.doFilter(request, response);
//        System.out.println("CustomLoggingFilter - Response Status: " + response.getStatus());
//    }
//}
