#!/bin/bash

/root/gowaf -port 9001 -backend http://web_php_5:80 &
/root/gowaf -port 9002 -backend http://web_php_7:80 &
/root/gowaf -port 9003 -backend http://web_java:8080 &

wait
