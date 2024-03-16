# morphenus（√）

## nmap扫描  

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.51 ((Debian))
81/tcp open  http    nginx 1.18.0
MAC Address: 00:0C:29:0B:D1:AC (VMware)
```

## web渗透  

![](img/2024-03-10-15-31-13.png)  
访问robots.txt是这样的结果  

![](img/2024-03-10-15-39-49.png)  

![](img/2024-03-10-15-58-23.png)  
![](img/2024-03-10-16-00-29.png)  
我们通过输入框向graffiti.txt输入内容，然后页面再读取txt文件内容，我想这里一个有lfi，但是模糊测试没测出来，然后我又想了一下  
这个可以写内容到文件里去，然后读的时候是读的graffiti.txt，所以我更改前端元素时它会一直加载。  
