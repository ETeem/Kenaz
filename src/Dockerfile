FROM alpine
MAINTAINER Ernest E. teem III <sovereign313@gmail.com>

ADD kenaz /kenaz
ADD kenaz.yaml /etc/kenaz.yaml
ADD keys/ /root/.ssh/

RUN apk update && apk add tzdata
RUN cp /usr/share/zoneinfo/US/Eastern /etc/localtime
RUN echo "US/Eastern" > /etc/timezone
RUN apk del tzdata && apk add git && apk add openrc && apk add ca-certificates

CMD ["/kenaz"]
