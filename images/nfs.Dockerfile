FROM docker.io/library/debian@sha256:89c1ea91e897f0fe0a3731595330bc45b8bdef4047464a07116f891a94054b31
COPY debs/ /debs/
RUN printf "#!/bin/sh\nexit 101\n" > /usr/sbin/policy-rc.d && chmod +x /usr/sbin/policy-rc.d && DEBIAN_FRONTEND=noninteractive dpkg -i /debs/*.deb && rm -rf /debs
COPY nfsplugin /nfsplugin
COPY licenses/ /usr/share/licenses/csi/
ENTRYPOINT ["/nfsplugin"]
