FROM quay.io/keycloak/keycloak:17.0.0 as builder

ENV KC_METRICS_ENABLED=true
# admin2,account2
ENV KC_FEATURES=authorization,account-api,admin-fine-grained-authz,impersonation,scripts,token-exchange,upload-scripts,web-authn,client-policies,ciba,map-storage,par,declarative-user-profile,dynamic-scopes,preview
ENV KC_DB=postgres
RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:17.0.0

COPY --from=builder /opt/keycloak/lib/quarkus/ /opt/keycloak/lib/quarkus/
WORKDIR /opt/keycloak
# for demonstration purposes only,please make sure to use proper certificates in production instead
# RUN keytool -genkeypair -storepass password -storetype PKCS12 -keyalg RSA -keysize 2048 -dname "CN=server" -alias server -ext "SAN:c=DNS:2Fpenguin.linux.test,IP:127.0.0.1" -keystore conf/server.keystore

# ENV KEYCLOAK_ADMIN=admin
# ENV KEYCLOAK_ADMIN_PASSWORD=admin
# change these values to point to a running postgres instance
# ENV KC_DB_URL=jdbc:postgresql://postgres/keycloak
# ENV KC_DB_URL=jdbc:postgresql://postgres:5432/keycloak
# ENV KC_DB_USERNAME=keycloak
# ENV KC_DB_PASSWORD=password
# ENV KC_HOSTNAME=localhost:8443
# ENV KC_HOSTNAME_STRICT=false
# ENV KC_HOSTNAME_STRICT_HTTPS=false
# ENV KC_PROXY_ADDRESS_FORWARDING=true
# ENV KC_HTTP_ENABLED=true

ENTRYPOINT ["/opt/keycloak/bin/kc.sh","start"]