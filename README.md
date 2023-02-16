# spring authorization server
spring authorization server 1.0 版本的自定义分离授权尝试:

### 注意点
* jdk 17
* springboot 版本 3.01

#### 模块服务器
<ul>
    <li> server 授权服务器</li>
    <li> client 官方客户端</li>
    <li> client1 自定客户端</li>
    <li> resource 需要访问的资源服务器</li>
</ul>

#### 认证授权相关的几个核心类
* OAuth2AuthorizationEndpointFilter
* OAuth2TokenEndpointFilter
* OAuth2AuthorizationCodeAuthenticationConverter

### 参考文档
过程中的参考文档如下:

* [Spring Security 官方文档](https://spring.io/projects/spring-authorization-server)
* [Github 官方源码](https://github.com/spring-projects/spring-authorization-server)
* [参考视频](https://www.bilibili.com/video/BV1Nd4y1V7Ys)
