FROM ubuntu

COPY gowaf /root/gowaf

COPY run.sh /root/run.sh

EXPOSE 9001

RUN chmod +x /root/run.sh

CMD ["/bin/bash", "-c", "/root/run.sh"]
