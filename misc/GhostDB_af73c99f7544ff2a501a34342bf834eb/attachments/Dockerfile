FROM thevlang/vlang:alpine AS builder

WORKDIR /app

COPY ./chall.v /app/chall.v

RUN v chall.v

FROM alpine:latest

RUN apk add --no-cache socat

WORKDIR /app

COPY --from=builder /app/chall /app/chall
COPY ./run.sh /app/run.sh
COPY ./flag /app/flag

RUN chmod +x /app/chall /app/run.sh

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:/app/run.sh"]