# nowafpls
Java 版本的 nowafpls

参考：https://github.com/assetnote/nowafpls

# nowafpls
大多数 Web 应用程序防火墙 (WAF) 对于发送请求正文时可以处理的数据量都有限制。这意味着对于包含请求主体的 HTTP 请求（即 POST、PUT、PATCH 等），通常可以通过简单地添加垃圾数据来绕过 WAF。 

当请求中填充了这些垃圾数据时，WAF 将处理最多 X kb 的请求并进行分析，但 WAF 限制之后的所有内容都将直接通过。

nowafpls 是一个简单的 Burp 插件，它会将这些垃圾数据插入到中继器选项卡内的 HTTP 请求中。您可以从预设数量的垃圾数据中进行选择，或者通过选择“自定义”选项插入任意数量的垃圾数据。


## 已记录的 WAF 限制

| WAF Provider          | Maximum Request Body Inspection Size Limit             |
|-----------------------|--------------------------------------------------------|
| Cloudflare            | 128 KB for ruleset engine, up to 500 MB for enterprise |
| AWS WAF               | 8 KB - 64 KB (configurable depending on service)       |
| Akamai                | 8 KB - 128 KB                                          |
| Azure WAF             | 128 KB                                                 |
| Fortiweb by Fortinet  | 100 MB                                                 |
| Barracuda WAF         | 64 KB                                                  |
| Sucuri                | 10 MB                                                  |
| Radware AppWall       | up to 1 GB for cloud WAF                               |
| F5 BIG-IP WAAP        | 20 MB (configurable)                                   |
| Palo Alto             | 10 MB                                                  |
| Cloud Armor by Google | 8 KB (can be increased to 128 KB)                      |


## License

MIT