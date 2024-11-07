ARG BUILD_FROM
ARG RUN_FROM=ubuntu:24.04

FROM ${BUILD_FROM} AS builder

COPY . /build

WORKDIR /build

RUN /build/build

FROM ${RUN_FROM} AS runner

WORKDIR /opt/converter

COPY --from=builder /build/dist/. /opt/converter/.

ENTRYPOINT ["/opt/converter/bin/emqx_data_converter"]
