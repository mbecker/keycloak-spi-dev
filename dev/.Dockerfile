FROM quay.io/keycloak/keycloak:17.0.0 as builder

# Define the arguments which are passed from Docker Compoe Build args
ARG KC_DB=postgres

ENV KC_METRICS_ENABLED=true
ENV KC_FEATURES=token-exchange,account2,admin2
ENV KC_DB=$KC_DB
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:17.0.0

COPY --from=builder /opt/keycloak/lib/quarkus/ /opt/keycloak/lib/quarkus/
WORKDIR /opt/keycloak
# for demonstration purposes only, please make sure to use proper certificates in production instead
RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=server" -alias server -ext "SAN:c=DNS:localhost,IP:127.0.0.1" -keystore conf/server.keystore


ENTRYPOINT ["/opt/keycloak/bin/kc.sh", "start"]