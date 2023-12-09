FROM joshuagoldman1994/prebuild_base:amd64
RUN mkdir /usr/app
COPY target/release/authentication-web-api  /usr/app/authentication-web-api 
COPY .env /usr/app/.env 
WORKDIR /usr/app
CMD ["./authentication-web-api"]
