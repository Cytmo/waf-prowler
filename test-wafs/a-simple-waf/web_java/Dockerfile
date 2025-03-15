FROM tomcat:9.0-jdk8-openjdk


# Copy WAR to the Tomcat webapps directory
COPY ./server/ROOT.war /usr/local/tomcat/webapps/


# Expose the port Tomcat is listening on
EXPOSE 8080

# Start Tomcat
CMD ["catalina.sh", "run"]
