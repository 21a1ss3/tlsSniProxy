FROM --platform=linux/arm/v7 alpine:latest

RUN mkdir /app && mkdir /app/bin && mkdir /app/conf
COPY tlsSniProxy /app/bin/
WORKDIR /app/bin/
ENTRYPOINT ["./tlsSniProxy"]
CMD /app/conf/config.json
