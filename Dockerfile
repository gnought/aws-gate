FROM python:3-alpine
ENV PYTHONUNBUFFERED=1

WORKDIR /code

ADD requirements/ /code/requirements

RUN apk add --no-cache --virtual .build-deps \
    build-base openssl-dev pkgconfig libffi-dev \
    cups-dev jpeg-dev && \
    # libc6-compat is needed for running session-manager-plugin
    apk add --no-cache libc6-compat openssh-client && \
    pip install --no-cache-dir -r /code/requirements/requirements.txt && \
    apk del .build-deps

COPY . ./
RUN pip install -e .
RUN aws-gate bootstrap && \
    mv ~/.aws-gate/bin/* /usr/local/bin/ && \
    rm -rf ~/.aws-gate

ENTRYPOINT ["aws-gate"]
CMD ["--help"]