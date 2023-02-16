package com.phantom.client1.web;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import cn.hutool.http.HttpUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;

/**
 * TODO
 *
 * @author lei.tan
 * @version 1.0
 * @date 2022/10/16 18:28
 */
@Slf4j
@RestController
public class GithubController {


    /**
     * 访问地址: <a href="https://github.com/login/oauth/authorize?client_id=Iv1.7e80ee6856b8dbe0">github</a>
     * <ul>
     *  <li>1. 浏览器访问地址登录 github 获取code</li>
     *  <li>2. 通过 code 获取到 token</li>
     *  <li>3. 通过 token 访问需要的资源</li>
     * </ul>
     *
     * @param code
     */
    @GetMapping("/callback/github")
    public void callback(String code) {
        log.info("回调的 code = {}", code);
        StringBuilder url = new StringBuilder();
        url.append("https://github.com/login/oauth/access_token");
        // 响应码
        url.append("?code=").append(code);
        // 从 GitHub 收到的 OAuth App 的客户端 ID [cbd5c7fce137455d770a]
        url.append("&client_id=").append("Iv1.7e80ee6856b8dbe0");
        // 从 GitHub 收到的 OAuth App 的客户端密码 [2caf16dc5b7abcb006b97451ee53c7fd24ffc3d8]
        url.append("&client_secret=").append("edd767a1c6cddd8fd9c6ec148e6388df46f442f4");
        // 非必填用户获得授权后被发送到的应用程序中的 URL
        // url.append("&redirect_uri=").append(code);// url
        // 通过 code 获取 token 信息
        String res = HttpUtil.post(url.toString(), "{}");
        log.info("获取到的结果信息 res: {}", res);
        String[] params = res.split("&");
        HashMap<String, String> authContent = new HashMap<>(6);
        for (String param : params) {
            String[] kv = param.split("=");
            if (kv.length > 1) {
                authContent.put(kv[0], kv[1]);
            }
        }
        // 通过 token 获取资源信息
        HttpRequest request = HttpUtil.createGet("https://api.github.com/user");
        // 设置请求头的 token 信息
        request.header("Authorization", "Bearer " + authContent.get("access_token"));
        HttpResponse response = request.execute();
        log.info("github.response => {}", response);
        log.info("github.response.body => {}", response.body());
    }


}
