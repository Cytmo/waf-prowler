# 使用官方的PHP 7.x Apache镜像
FROM php:7-apache

# 安装mysqli扩展
RUN docker-php-ext-install mysqli

# 启用Apache mod_rewrite模块
RUN a2enmod rewrite

# 复制源代码到容器中的Apache服务器根目录下
COPY server/* /var/www/html/

# 修改文件权限
RUN mkdir /var/www/html/uploads && chmod 777 /var/www/html/uploads
