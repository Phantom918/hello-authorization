package com.phantom.client1.web;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import cn.hutool.http.HttpUtil;
import cn.hutool.json.JSONObject;
import cn.hutool.json.JSONUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;

/**
 * TODO
 *
 * @author lei.tan
 * @version 1.0
 * @date 2023/2/14 14:10
 */
@Slf4j
@Controller
public class IndexController {


    @GetMapping("/")
    public void getAuthorizationPage(HttpServletResponse response) throws IOException {
        String urlBuilder = "http://127.0.0.1:9000/my/authorize" +
                "?response_type=code" +
                "&client_id=client1" +
                "&scope=message.read message.write openid" +
                "&redirect_uri=http://127.0.0.1:8081/callback";
        response.sendRedirect(urlBuilder);
    }


    @ResponseBody
    @GetMapping("/callback")
    public String callback(String code) {
        log.info("callback ==> code: {}", code);
        HttpResponse response = HttpUtil.createPost("http://127.0.0.1:9000/oauth2/token")
                .form("grant_type", "authorization_code")
                .form("code", code)
                .form("redirect_uri", "http://127.0.0.1:8081/callback")
                .form("client_id", "client1")
                .form("client_secret", "123456")
                .execute();
        log.info("response: {}", response);
        JSONObject body = JSONUtil.parseObj(response.body());
        log.info("body: {}", body);
        String access_token = body.getStr("access_token");
        log.info("access_token: {}", access_token);
        String id_token = body.getStr("id_token");
        log.info("id_token: {}", id_token);

        HttpResponse httpResponse = HttpUtil.createGet("http://127.0.0.1:8090/messages")
                .header("Authorization", "Bearer " + access_token)
                .execute();
        log.info("资源服务器返回信息 = {}", httpResponse);

        HttpResponse httpResponse1 = HttpUtil.createGet("http://127.0.0.1:8090/messages")
                .header("Authorization", "Bearer " + id_token)
                .execute();
        log.info("资源服务器返回信息1 = {}", httpResponse1);


        return httpResponse.body();

    }

}
