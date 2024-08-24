# 使用官方的PHP 5.x Apache镜像
FROM php:5-apache

# 安装MySQL的PHP扩展
RUN docker-php-ext-install mysql mysqli pdo pdo_mysql

# 将PHP源代码复制到容器中的Apache服务器根目录下


COPY server/* /var/www/html/

RUN a2enmod rewrite

# 创建上传目录并设置合适的权限
RUN mkdir /var/www/html/uploads && chmod 777 /var/www/html/uploads
