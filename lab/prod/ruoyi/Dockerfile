# NOTE: no `# syntax=docker/dockerfile:1.4` line on purpose. BuildKit would
# fetch that frontend image from Docker Hub, which is unreachable in the
# target lab environment; this Dockerfile uses only built-in instructions.
# ---------------------------------------------------------------------------
# RuoYi 4.7.8 (official Thymeleaf/Shiro single application) — production-lab image
#
# Stage 1 fetches the official source (Gitee mirror first, GitHub tag archive
# second, a locally mounted/copied tree first of all) and builds ruoyi-admin.jar.
# Stage 2 is a JRE-only runtime, non-root, with the profile/upload and log dirs
# writable.
#
# Build arguments:
#   RUOYI_VERSION    git tag / release tag (default v4.7.8)
#   GITEE_REPO       Gitee clone URL
#   GITHUB_ZIP_URL   fallback source archive (.tar.gz)
#   MAVEN_MIRROR     optional Maven Central mirror, e.g.
#                    https://maven.aliyun.com/repository/public
#   HTTP_PROXY / HTTPS_PROXY / NO_PROXY  consumed by BuildKit for git/curl/maven
#
# Offline / source-drop alternative:
#   git clone --depth 1 -b v4.7.8 https://gitee.com/y_project/RuoYi.git \
#       lab/prod/ruoyi/RuoYi
#   docker compose -f lab/prod/docker-compose.yml build ruoyi
# The Dockerfile uses the local tree when ./RuoYi/pom.xml exists.
# ---------------------------------------------------------------------------
FROM maven:3.8-openjdk-8 AS builder

ARG RUOYI_VERSION=v4.7.8
ARG GITEE_REPO=https://gitee.com/y_project/RuoYi.git
ARG GITHUB_ZIP_URL=https://github.com/yangzongzhuan/RuoYi/archive/refs/tags/v4.7.8.tar.gz
ARG MAVEN_MIRROR=
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

# maven:3.8-openjdk-8 already ships git/curl/wget/tar/unzip. Do NOT apt-get
# here: many lab hosts cannot reach deb.debian.org, and the install was only
# defensive. Keeping this layer out makes the build work behind registry /
# Gitee / Maven mirrors without a Debian mirror.

# Copy the whole (small) build context so a manually supplied ./RuoYi tree is
# picked up without a conditional COPY that would fail when it is absent.
COPY . /ctx

RUN set -eux; \
    mkdir -p /build; \
    if [ -f /ctx/RuoYi/pom.xml ]; then \
        echo ">>> source: local ./RuoYi (manual drop)"; \
        cp -a /ctx/RuoYi /build/RuoYi; \
    elif git clone --depth 1 --single-branch --branch "${RUOYI_VERSION}" \
            "${GITEE_REPO}" /build/RuoYi; then \
        echo ">>> source: gitee ${GITEE_REPO} @ ${RUOYI_VERSION}"; \
    else \
        echo ">>> Gitee clone failed, trying GitHub archive..." >&2; \
        rm -rf /build/RuoYi /tmp/ruoyi-src; \
        mkdir -p /tmp/ruoyi-src; \
        if curl -fsSL --retry 3 --connect-timeout 20 \
                -o /tmp/ruoyi.tar.gz "${GITHUB_ZIP_URL}" \
           && tar -xzf /tmp/ruoyi.tar.gz -C /tmp/ruoyi-src \
           && mv /tmp/ruoyi-src/* /build/RuoYi; then \
            echo ">>> source: github ${GITHUB_ZIP_URL}"; \
        else \
            echo "============================================================" >&2; \
            echo "ERROR: cannot fetch RuoYi ${RUOYI_VERSION}" >&2; \
            echo "" >&2; \
            echo "Both source transports failed. Fix one of:" >&2; \
            echo "  1) proxy:  docker compose build \\" >&2; \
            echo "             --build-arg HTTPS_PROXY=http://host:port ruoyi" >&2; \
            echo "  2) mirror: set GITEE_REPO / GITHUB_ZIP_URL in lab/prod/.env" >&2; \
            echo "  3) manual source drop:" >&2; \
            echo "       git clone --depth 1 -b ${RUOYI_VERSION} \\" >&2; \
            echo "         https://gitee.com/y_project/RuoYi.git \\" >&2; \
            echo "         lab/prod/ruoyi/RuoYi" >&2; \
            echo "       docker compose -f lab/prod/docker-compose.yml build ruoyi" >&2; \
            echo "============================================================" >&2; \
            exit 1; \
        fi; \
    fi; \
    test -f /build/RuoYi/pom.xml

# Optional Maven Central mirror. Written only when MAVEN_MIRROR is non-empty,
# so an empty value keeps the upstream default (repo.maven.apache.org).
RUN set -eux; \
    if [ -n "${MAVEN_MIRROR}" ]; then \
        mkdir -p /root/.m2; \
        printf '%s\n' \
          '<settings xmlns="http://maven.apache.org/SETTINGS/1.0.0">' \
          '  <mirrors>' \
          '    <mirror>' \
          '      <id>lab-mirror</id>' \
          '      <name>lab mirror</name>' \
          "      <url>${MAVEN_MIRROR}</url>" \
          '      <mirrorOf>central</mirrorOf>' \
          '    </mirror>' \
          '  </mirrors>' \
          '</settings>' > /root/.m2/settings.xml; \
        echo ">>> Maven mirror: ${MAVEN_MIRROR}"; \
    fi; \
    cd /build/RuoYi; \
    mvn -B -ntp -DskipTests -Dmaven.test.skip=true package; \
    test -f ruoyi-admin/target/ruoyi-admin.jar

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM eclipse-temurin:8-jre

ARG RUOYI_VERSION=v4.7.8
LABEL org.opencontainers.image.title="RuoYi ${RUOYI_VERSION} prod lab" \
      org.opencontainers.image.description="Official RuoYi 4.7.8 for ruoyi-scan detection/false-positive testing" \
      org.opencontainers.image.source="https://gitee.com/y_project/RuoYi"

ENV TZ=Asia/Shanghai \
    LANG=C.UTF-8 \
    JAVA_OPTS="-Xms256m -Xmx512m -XX:+UseG1GC -Dfile.encoding=UTF-8"

# eclipse-temurin:8-jre already ships curl, wget, bash and tzdata (verified:
# /usr/share/zoneinfo/Asia/Shanghai exists), so no apt-get is needed.
# logback.xml hardcodes /home/ruoyi/logs; curl is used by the healthcheck.
RUN set -eux; \
    groupadd --system ry; \
    useradd --system --gid ry --home-dir /home/ruoyi --create-home ry; \
    mkdir -p /home/ruoyi/logs /home/ruoyi/uploadPath /app; \
    chown -R ry:ry /home/ruoyi /app

WORKDIR /home/ruoyi

COPY --from=builder /build/RuoYi/ruoyi-admin/target/ruoyi-admin.jar /app/ruoyi-admin.jar
RUN chown ry:ry /app/ruoyi-admin.jar

USER ry
EXPOSE 8080

# /login is anonymous in ShiroConfig; a 200 means the MVC stack is ready.
HEALTHCHECK --interval=15s --timeout=5s --start-period=120s --retries=20 \
  CMD curl -fsS -o /dev/null http://127.0.0.1:8080/login || exit 1

# --server.port overrides application.yml (default 80); --ruoyi.profile
# overrides the Windows path D:/ruoyi/uploadPath baked into the upstream yml.
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar /app/ruoyi-admin.jar --server.port=8080 --ruoyi.profile=/home/ruoyi/uploadPath \"$@\"", "ruoyi"]
