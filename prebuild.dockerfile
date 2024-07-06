FROM joshuagoldman1994/prebuild_base:1.0.0
RUN mkdir /usr/app
COPY target/release/two_factor_auth_gen  /usr/app/two_factor_auth_gen 
COPY .env /usr/app/.env 
WORKDIR /usr/app
CMD ["./two_factor_auth_gen"]
