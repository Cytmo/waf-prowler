# 使用官方MySQL 5.7镜像
FROM mysql:5.7

# 设置环境变量，以确保MySQL服务可以正常运行，不要求交互式密码输入
ENV MYSQL_ROOT_PASSWORD=rootpassword
ENV MYSQL_DATABASE=vulnerable_db

# 将初始化SQL脚本添加到容器内部执行的位置
COPY init.sql /docker-entrypoint-initdb.d/
